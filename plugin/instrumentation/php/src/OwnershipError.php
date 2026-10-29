<?php
declare(strict_types=1);

namespace AuthzRadar;

/** Thrown in enforce mode when the resource belongs to someone else. Map it to 403 or 404. */
final class OwnershipError extends \RuntimeException
{
    public function __construct(public readonly ?string $resourceType = null)
    {
        parent::__construct('ownership check failed', 403);
    }
}
