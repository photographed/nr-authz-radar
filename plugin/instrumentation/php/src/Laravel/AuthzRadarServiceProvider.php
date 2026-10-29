<?php
declare(strict_types=1);

namespace AuthzRadar\Laravel;

use AuthzRadar\Agent;
use AuthzRadar\NewRelicAgent;
use AuthzRadar\Pseudonymizer;
use AuthzRadar\Telemetry;
use Illuminate\Auth\Access\Events\GateEvaluated;
use Illuminate\Auth\Access\Response;
use Illuminate\Auth\Events\Failed;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

/** Auto-discovered. Registers the per-request Telemetry, the middleware and the auth listeners. */
final class AuthzRadarServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../../config/authz-radar.php', 'authz-radar');
        $this->app->bindIf(Agent::class, NewRelicAgent::class, true);
        // scoped: one per request, also reset between requests on Octane
        $this->app->scoped(Telemetry::class, function ($app) {
            $c = $app['config']['authz-radar'];
            $log = null;
            if ($c['log_decisions']) {
                $channel = $c['log_channel'];
                $log = static fn (string $line) => ($channel ? Log::channel($channel) : Log::getFacadeRoot())->info($line);
            }
            return new Telemetry(
                $app->make(Agent::class),
                new Pseudonymizer((string) $c['hmac_key']),
                $c['attributes'] === Telemetry::FULL ? Telemetry::FULL : Telemetry::MINIMAL,
                $c['ownership_mode'] === Telemetry::OBSERVE ? Telemetry::OBSERVE : Telemetry::ENFORCE,
                (bool) $c['notice_denials'],
                $log,
            );
        });
    }

    public function boot(Router $router): void
    {
        $this->publishes([__DIR__ . '/../../config/authz-radar.php' => config_path('authz-radar.php')], 'authz-radar-config');
        $router->aliasMiddleware('authz.owner', CheckOwnership::class);
        $router->aliasMiddleware('authz.radar', RecordRequest::class);
        if (!config('authz-radar.enabled')) {
            return;
        }
        if (config('authz-radar.auto_middleware')) {
            $router->pushMiddlewareToGroup('web', RecordRequest::class);
            $router->pushMiddlewareToGroup('api', RecordRequest::class);
        }

        // A failed Gate check is only remembered here. It becomes a deny when the response is
        // 403 (RecordRequest), because @can in a view also evaluates abilities without denying.
        Event::listen(GateEvaluated::class, function (GateEvaluated $e): void {
            $allowed = $e->result instanceof Response ? $e->result->allowed() : (bool) $e->result;
            $t = $this->app->make(Telemetry::class);
            if ($allowed) {
                if ($t->currentRequiredScope() === null) {
                    $t->requiredScope('ability:' . $e->ability);
                }
                return;
            }
            RecordRequest::rememberFailedGate($t, $e->user === null, $e->ability);
        });

        // Login failures (credential stuffing, D10 / D11)
        Event::listen(Failed::class, function (): void {
            $this->app->make(Telemetry::class)->deny('unauthenticated');
        });
    }
}
