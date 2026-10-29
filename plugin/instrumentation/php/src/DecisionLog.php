<?php
declare(strict_types=1);

namespace AuthzRadar;

/**
 * The fixed log line from shared/attribute-spec.md ("認可判断のログ行"). No user, resource or IP
 * values: the trace ID added by Logs in context links the line to the transaction.
 */
final class DecisionLog
{
    public static function line(string $decision, ?bool $ownerMatch, ?string $reason, ?string $resourceType,
                                ?string $operation, ?string $bypass = null): string
    {
        $line = 'authz-radar decision=' . self::token($decision)
            . ' owner_match=' . ($ownerMatch === null ? '-' : ($ownerMatch ? 'true' : 'false'))
            . ' reason=' . self::token($reason)
            . ' resource.type=' . self::token($resourceType)
            . ' api.operation=' . self::token($operation);
        return $bypass === null ? $line : $line . ' bypass=' . self::token($bypass);
    }

    private static function token(?string $value): string
    {
        if ($value === null || trim($value) === '') {
            return '-';
        }
        return substr((string) preg_replace('/\s+/', '_', $value), 0, 64);
    }
}
