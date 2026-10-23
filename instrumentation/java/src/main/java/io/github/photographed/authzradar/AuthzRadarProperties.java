package io.github.photographed.authzradar;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** {@code nr.authz-radar.*} */
@ConfigurationProperties(prefix = "nr.authz-radar")
public class AuthzRadarProperties {

    /** Turns the whole library off. */
    private boolean enabled = true;

    /**
     * Which attributes to send. {@code MINIMAL} (stage S2): decision, owner_match, enduser.id.
     * {@code FULL} (stage S3): everything in shared/attribute-spec.md.
     */
    private AuthzTelemetry.AttributeSet attributes = AuthzTelemetry.AttributeSet.MINIMAL;

    /**
     * Secret for HMAC pseudonyms of user IDs and API keys. Without it, enduser.id and
     * api.key_id are not sent at all. Load it from a secret store, never commit it.
     */
    private String hmacKey;

    /** What {@code @CheckOwnership} does on a mismatch: ENFORCE (deny) or OBSERVE (record only). */
    private CheckOwnership.OwnershipMode ownershipMode = CheckOwnership.OwnershipMode.ENFORCE;

    /**
     * Write a structured log line for denials and allowed owner mismatches (no user IDs).
     * For high-security mode, where custom attributes cannot be sent, and as the logs last mile.
     */
    private boolean logDecisions = false;

    /** Authorities allowed to read other owners' resources, e.g. {@code SCOPE_admin:read}. */
    private List<String> bypassAuthorities = new ArrayList<>();

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public AuthzTelemetry.AttributeSet getAttributes() { return attributes; }
    public void setAttributes(AuthzTelemetry.AttributeSet attributes) { this.attributes = attributes; }
    public String getHmacKey() { return hmacKey; }
    public void setHmacKey(String hmacKey) { this.hmacKey = hmacKey; }
    public CheckOwnership.OwnershipMode getOwnershipMode() { return ownershipMode; }
    public void setOwnershipMode(CheckOwnership.OwnershipMode ownershipMode) { this.ownershipMode = ownershipMode; }
    public boolean isLogDecisions() { return logDecisions; }
    public void setLogDecisions(boolean logDecisions) { this.logDecisions = logDecisions; }
    public List<String> getBypassAuthorities() { return bypassAuthorities; }
    public void setBypassAuthorities(List<String> bypassAuthorities) { this.bypassAuthorities = bypassAuthorities; }
}
