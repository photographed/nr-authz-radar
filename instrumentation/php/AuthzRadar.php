<?php
declare(strict_types=1);

/**
 * nr-authz-radar stage S2 for PHP.
 *
 * Sends resource.owner_match and authz.decision (shared/attribute-spec.md) and a pseudonymized
 * enduser.id. Call checkOwnership() right after loading a resource by a client-supplied ID.
 *
 * UNVERIFIED: the PHP agent is a C extension, so the function names below
 * (newrelic_add_custom_parameter, newrelic_set_user_id, newrelic_notice_error) were not checked
 * against an installed agent. Missing functions are skipped, never fatal. The PHP agent has no
 * "expected" flag on newrelic_notice_error that we could confirm: configure expected errors in
 * newrelic.ini instead (check your agent's docs).
 */

namespace AuthzRadar;

final class OwnershipError extends \RuntimeException
{
    public function __construct()
    {
        parent::__construct('ownership check failed', 403);
    }
}

/** One per request: keeps owner_match sticky and lets deny win over allow. */
final class RequestState
{
    public bool $mismatch = false;
    public bool $denied = false;
}

final class AuthzRadar
{
    /** @var array<string, callable> */
    private array $api;

    /** @param array<string, callable>|null $api inject for tests; defaults to the agent functions */
    public function __construct(?array $api = null)
    {
        $this->api = $api ?? [
            'attr' => static fn (string $k, $v) => \function_exists('newrelic_add_custom_parameter') ? newrelic_add_custom_parameter($k, $v) : null,
            'user' => static fn (string $v) => \function_exists('newrelic_set_user_id') ? newrelic_set_user_id($v) : null,
            'error' => static fn (\Throwable $e) => \function_exists('newrelic_notice_error') ? newrelic_notice_error($e) : null,
        ];
    }

    /** 'u_' + 16 hex chars, or null without a key (a plain hash can be brute-forced). */
    public static function pseudonym($userId, string $key): ?string
    {
        if ($key === '' || $userId === null) {
            return null;
        }
        return 'u_' . substr(hash_hmac('sha256', (string) $userId, $key), 0, 16);
    }

    public function setUser($userId, string $key): void
    {
        $value = self::pseudonym($userId, $key);
        if ($value !== null) {
            ($this->api['user'])($value);
        }
    }

    /**
     * $enforce = false (observe) lets mismatches through so detection D01 shows real IDORs.
     * $bypassScope marks legitimate cross-owner access (e.g. 'admin:read') so D01 excludes it.
     */
    public function checkOwnership($ownerId, $currentUserId, RequestState $state, bool $enforce = true, ?string $bypassScope = null): bool
    {
        $match = $currentUserId !== null && (string) $ownerId === (string) $currentUserId;
        if (!$match) {
            $state->mismatch = true;
        }
        ($this->api['attr'])('resource.owner_match', !$state->mismatch);
        if (!$match && $bypassScope !== null) {
            ($this->api['attr'])('authz.required_scope', $bypassScope);
        } elseif (!$match && $enforce) {
            $state->denied = true;
            ($this->api['attr'])('authz.decision', 'deny');
            $error = new OwnershipError();
            ($this->api['error'])($error);
            throw $error;
        }
        if (!$state->denied) {
            ($this->api['attr'])('authz.decision', 'allow');
        }
        return $match;
    }
}
