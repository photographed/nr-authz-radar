<?php
declare(strict_types=1);

namespace AuthzRadar\Laravel;

use AuthzRadar\Telemetry;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Per request: pseudonymized enduser.id, granted scopes (Sanctum token abilities, FULL), and a
 * deny for 401 / 403 responses that no check recorded yet. Added to 'web' and 'api' by default.
 */
final class RecordRequest
{
    /** @var \WeakMap<\AuthzRadar\RequestState, array{0: bool, 1: string}>|null */
    private static ?\WeakMap $failedGates = null;

    public function __construct(private readonly Telemetry $telemetry)
    {
    }

    public static function rememberFailedGate(Telemetry $t, bool $guest, string $ability): void
    {
        self::$failedGates ??= new \WeakMap();
        self::$failedGates[$t->state()] ??= [$guest, $ability];
    }

    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $user = $request->user();
        if ($user !== null) {
            $this->telemetry->user($user->getAuthIdentifier());
            if (method_exists($user, 'currentAccessToken') && ($token = $user->currentAccessToken()) !== null
                && isset($token->abilities) && \is_array($token->abilities)) {
                $this->telemetry->grantedScopes($token->abilities);
                $this->telemetry->clientType('api_key');
            }
        }
        $status = $response->getStatusCode();
        if (($status === 401 || $status === 403) && $this->telemetry->state()->decision !== 'deny') {
            $this->telemetry->deny($this->reason($status, $user === null));
        }
        return $response;
    }

    private function reason(int $status, bool $guest): ?string
    {
        if ($status === 401 || $guest) {
            return 'unauthenticated';
        }
        $gate = self::$failedGates[$this->telemetry->state()] ?? null;
        if ($gate === null) {
            return null; // a 403 from somewhere we cannot see: reason unknown, do not guess
        }
        // Name role checks 'role:…' / 'role-…' to get role_missing; any other ability is a scope / permission
        return str_starts_with($gate[1], 'role') ? 'role_missing' : 'scope_missing';
    }
}
