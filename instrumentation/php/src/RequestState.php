<?php
declare(strict_types=1);

namespace AuthzRadar;

/**
 * One per request (or per WebSocket message). Keeps owner_match sticky, lets deny win over allow
 * and keeps the first known deny reason. Do not share it between requests (Octane, queues).
 */
final class RequestState
{
    public ?string $decision = null;
    public ?string $denyReason = null;
    public ?string $requiredScope = null;
    public ?string $resourceType = null;
    public bool $ownerMismatch = false;
    public bool $mismatchLogged = false;
    public int $checkCount = 0;
    /** @var array<string, true> */
    public array $operations = [];
}
