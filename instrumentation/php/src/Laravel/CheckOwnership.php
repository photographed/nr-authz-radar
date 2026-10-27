<?php
declare(strict_types=1);

namespace AuthzRadar\Laravel;

use AuthzRadar\OwnershipError;
use AuthzRadar\Telemetry;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware for route model binding:
 *
 *   Route::get('/orders/{order}', ...)->middleware('authz.owner:order');            // orders.user_id
 *   Route::get('/teams/{team}', ...)->middleware('authz.owner:team,owner_id,team');  // column, resource.type
 *
 * Compares the bound model's owner column with the signed-in user. A mismatch is blocked with
 * config('authz-radar.deny_status') in enforce mode, or let through and recorded in observe mode.
 */
final class CheckOwnership
{
    public function __construct(private readonly Telemetry $telemetry)
    {
    }

    public function handle(Request $request, Closure $next, string $parameter, string $column = 'user_id', ?string $type = null): Response
    {
        $model = $request->route($parameter);
        if (!\is_object($model)) {
            // Not bound to a model (no SubstituteBindings, or a plain ID): nothing to compare.
            // Check in the controller instead (ChecksOwnership).
            return $next($request);
        }
        $user = $request->user();
        try {
            $this->telemetry->checkOwnership(data_get($model, $column), $user?->getAuthIdentifier(), $type ?? $parameter, self::bypass($user));
        } catch (OwnershipError) {
            abort((int) config('authz-radar.deny_status', 404));
        }
        return $next($request);
    }

    /** The first configured bypass ability the user has, or null. */
    public static function bypass(mixed $user): ?string
    {
        if ($user === null) {
            return null;
        }
        foreach ((array) config('authz-radar.bypass_abilities', []) as $ability) {
            if (Gate::forUser($user)->allows($ability)) {
                return (string) $ability;
            }
        }
        return null;
    }
}
