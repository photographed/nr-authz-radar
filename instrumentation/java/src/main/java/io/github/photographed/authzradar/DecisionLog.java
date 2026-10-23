package io.github.photographed.authzradar;

/**
 * Optional structured log line for authorization decisions (shared/attribute-spec.md,
 * "認可判断のログ行"). Written only for denials and for owner mismatches that were let through,
 * never for ordinary allows, and never with user IDs: Logs in context links the line to the
 * trace, which carries the pseudonymous user. Used where custom attributes cannot be sent
 * (high-security mode) and as the last mile for evidence (L01, L04).
 */
@FunctionalInterface
public interface DecisionLog {

    void write(String line);

    static String line(String decision, Boolean ownerMatch, String reason, String resourceType,
                       String operation, String bypass) {
        StringBuilder sb = new StringBuilder("authz-radar decision=").append(token(decision))
                .append(" owner_match=").append(ownerMatch == null ? "-" : ownerMatch)
                .append(" reason=").append(token(reason))
                .append(" resource.type=").append(token(resourceType))
                .append(" api.operation=").append(token(operation));
        if (bypass != null) {
            sb.append(" bypass=").append(token(bypass));
        }
        return sb.toString();
    }

    private static String token(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        String t = value.replaceAll("\\s+", "_");
        return t.length() > 64 ? t.substring(0, 64) : t;
    }
}
