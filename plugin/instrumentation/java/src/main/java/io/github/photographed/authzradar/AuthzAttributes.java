package io.github.photographed.authzradar;

/**
 * Attribute names and enumerated values from {@code shared/attribute-spec.md} (schema 0.2).
 * Keep these in sync with the spec: the same NRQL must work for every language.
 */
public final class AuthzAttributes {

    public static final String REQUIRED_SCOPE = "authz.required_scope";
    public static final String GRANTED_SCOPES = "authz.granted_scopes";
    public static final String DECISION = "authz.decision";
    public static final String DENY_REASON = "authz.deny_reason";
    public static final String RESOURCE_TYPE = "resource.type";
    public static final String OWNER_MATCH = "resource.owner_match";
    public static final String CLIENT_TYPE = "client.type";
    public static final String API_KEY_ID = "api.key_id";
    public static final String TOKEN_AGE_SEC = "auth.token_age_sec";
    public static final String PROTOCOL = "api.protocol";
    public static final String OPERATION = "api.operation";
    public static final String CHECK_COUNT = "resource.check_count";

    public static final String ALLOW = "allow";
    public static final String DENY = "deny";

    public static final String REASON_OWNER_MISMATCH = "owner_mismatch";
    public static final String REASON_SCOPE_MISSING = "scope_missing";
    public static final String REASON_ROLE_MISSING = "role_missing";
    public static final String REASON_TENANT_MISMATCH = "tenant_mismatch";
    public static final String REASON_UNAUTHENTICATED = "unauthenticated";

    /** Recorded as {@link #REQUIRED_SCOPE} when an endpoint declares no scope or role at all. */
    public static final String SCOPE_NONE = "none";

    private AuthzAttributes() {
    }
}
