<?php
declare(strict_types=1);

namespace AuthzRadar;

/**
 * Records authorization telemetry for one request (shared/attribute-spec.md, schema 0.3).
 *
 * MINIMAL (stage S2, default) sends authz.decision, resource.owner_match, enduser.id, and the
 * attributes detections need to stay correct (bypass scope, api.protocol / api.operation).
 * FULL (stage S3) adds the rest.
 *
 * Rules: deny always wins over allow; the first known deny reason wins; owner_match is sticky
 * (once a mismatch is seen it stays false); raw identifiers are never sent.
 */
final class Telemetry
{
    public const MINIMAL = 'minimal';
    public const FULL = 'full';
    public const OBSERVE = 'observe';
    public const ENFORCE = 'enforce';
    public const REASONS = ['owner_mismatch', 'scope_missing', 'role_missing', 'tenant_mismatch', 'unauthenticated'];
    private const MAX_OPERATIONS = 3;

    private RequestState $state;
    /** @var (callable(string): void)|null */
    private $decisionLog;

    /**
     * @param string $ownershipMode ENFORCE throws OwnershipError on a mismatch; OBSERVE lets it
     *        through so detection D01 shows IDORs that really happen (start here on existing apps)
     * @param bool $noticeDenials send denials as errors. Off by default: the PHP agent has no
     *        "expected" flag, so they would raise the error rate
     * @param (callable(string): void)|null $decisionLog receives the decision log line, or null
     */
    public function __construct(
        private readonly Agent $agent,
        private readonly Pseudonymizer $pseudonymizer,
        private readonly string $attributes = self::MINIMAL,
        private readonly string $ownershipMode = self::ENFORCE,
        private readonly bool $noticeDenials = false,
        ?callable $decisionLog = null,
        ?RequestState $state = null,
    ) {
        $this->decisionLog = $decisionLog;
        $this->state = $state ?? new RequestState();
    }

    public function state(): RequestState
    {
        return $this->state;
    }

    /** For work outside an HTTP request (a WebSocket message, a queued job): start a fresh state. */
    public function reset(): void
    {
        $this->state = new RequestState();
    }

    public function user(int|string|null $userId): void
    {
        $id = $this->pseudonymizer->user($userId);
        if ($id !== null) {
            $this->agent->userId($id);
        }
    }

    /**
     * Call right after loading a resource by a client-supplied ID.
     *
     * @param string|null $bypassScope marks legitimate cross-owner access (e.g. 'admin:read');
     *        detection D01 excludes it. Always sent, also in MINIMAL
     * @param bool|null $enforce override the configured mode for this call
     * @throws OwnershipError on a mismatch in enforce mode (without a bypass scope)
     */
    public function checkOwnership(int|string|null $ownerId, int|string|null $currentUserId, ?string $resourceType = null,
                                   ?string $bypassScope = null, ?bool $enforce = null): bool
    {
        $match = $currentUserId !== null && $ownerId !== null && (string) $ownerId === (string) $currentUserId;
        $this->ownership($resourceType, $match);
        if ($match) {
            $this->allow();
            return true;
        }
        if ($bypassScope !== null && $bypassScope !== '') {
            $this->bypass($bypassScope);
            $this->allow();
            $this->mismatchLetThrough($bypassScope);
            return false;
        }
        if ($enforce ?? $this->ownershipMode === self::ENFORCE) {
            $error = new OwnershipError($resourceType);
            $this->deny('owner_mismatch', $error);
            throw $error;
        }
        $this->allow();
        $this->mismatchLetThrough(null);
        return false;
    }

    public function ownership(?string $resourceType, bool $ownerMatches): void
    {
        $s = $this->state;
        if ($resourceType !== null && $resourceType !== '') {
            $s->resourceType = $resourceType;
            if ($this->full()) {
                $this->agent->attribute('resource.type', $resourceType);
            }
        }
        if (!$ownerMatches) {
            $s->ownerMismatch = true;
        }
        $s->checkCount++;
        $this->agent->attribute('resource.owner_match', !$s->ownerMismatch);
        if ($this->full()) {
            $this->agent->attribute('resource.check_count', $s->checkCount);
        }
    }

    public function allow(): void
    {
        if ($this->state->decision === null) {
            $this->state->decision = 'allow';
            $this->agent->attribute('authz.decision', 'allow');
        }
    }

    /** @param string|null $reason one of REASONS, or null when unknown */
    public function deny(?string $reason, ?\Throwable $cause = null): void
    {
        $s = $this->state;
        $first = $s->decision !== 'deny';
        $s->decision = 'deny';
        $this->agent->attribute('authz.decision', 'deny');
        if ($reason !== null && \in_array($reason, self::REASONS, true) && $s->denyReason === null) {
            $s->denyReason = $reason;
            if ($this->full()) {
                $this->agent->attribute('authz.deny_reason', $reason);
            }
        }
        if ($first && $cause !== null && $this->noticeDenials) {
            $this->agent->noticeError($cause);
        }
        if ($first) {
            $this->log(DecisionLog::line('deny', $s->ownerMismatch ? false : null, $s->denyReason, $s->resourceType, $this->operation()));
        }
    }

    public function decisionRecorded(): bool
    {
        return $this->state->decision !== null;
    }

    public function requiredScope(string $scope): void
    {
        $this->state->requiredScope = $scope;
        if ($this->full()) {
            $this->agent->attribute('authz.required_scope', $scope);
        }
    }

    public function currentRequiredScope(): ?string
    {
        return $this->state->requiredScope;
    }

    /** Legitimate cross-owner access (admin / support). Always sent: D01 needs it to exclude these. */
    public function bypass(string $scope): void
    {
        $this->state->requiredScope = $scope;
        $this->agent->attribute('authz.required_scope', $scope);
    }

    /** @param iterable<string> $scopes */
    public function grantedScopes(iterable $scopes): void
    {
        $list = array_values(array_unique(array_map('strval', \is_array($scopes) ? $scopes : iterator_to_array($scopes, false))));
        if (!$this->full() || $list === []) {
            return;
        }
        sort($list);
        $this->agent->attribute('authz.granted_scopes', implode(',', $list));
    }

    /** @param string $clientType web / mobile / api_key / service / unknown. Decide it from how the request authenticated, not from a header the client sets. */
    public function clientType(string $clientType): void
    {
        if ($this->full() && \in_array($clientType, ['web', 'mobile', 'api_key', 'service', 'unknown'], true)) {
            $this->agent->attribute('client.type', $clientType);
        }
    }

    public function apiKey(?string $rawApiKey): void
    {
        $id = $this->full() ? $this->pseudonymizer->apiKey($rawApiKey) : null;
        if ($id !== null) {
            $this->agent->attribute('api.key_id', $id);
        }
    }

    public function tokenAgeSeconds(int $seconds): void
    {
        if ($this->full() && $seconds >= 0) {
            $this->agent->attribute('auth.token_age_sec', $seconds);
        }
    }

    /**
     * api.protocol and the server-side api.operation (shared/protocols.md). Sent in MINIMAL too.
     * Never pass the client-supplied GraphQL operation name: it can be spoofed.
     */
    public function protocol(string $protocol, ?string $operation = null): void
    {
        $this->agent->attribute('api.protocol', $protocol);
        if ($operation === null || $operation === '') {
            return;
        }
        $this->state->operations[$operation] = true;
        $ops = array_keys($this->state->operations);
        sort($ops);
        $joined = implode(',', \array_slice($ops, 0, self::MAX_OPERATIONS));
        $this->agent->attribute('api.operation', \count($ops) > self::MAX_OPERATIONS ? $joined . ',…' : $joined);
    }

    private function mismatchLetThrough(?string $bypassScope): void
    {
        if (!$this->state->mismatchLogged) {
            $this->state->mismatchLogged = true;
            $this->log(DecisionLog::line('allow', false, null, $this->state->resourceType, $this->operation(), $bypassScope));
        }
    }

    private function operation(): ?string
    {
        if ($this->state->operations === []) {
            return null;
        }
        $ops = array_keys($this->state->operations);
        sort($ops);
        return implode(',', $ops);
    }

    private function log(string $line): void
    {
        if ($this->decisionLog !== null) {
            ($this->decisionLog)($line);
        }
    }

    private function full(): bool
    {
        return $this->attributes === self::FULL;
    }
}
