package io.github.photographed.authzradar;

import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Records authorization telemetry for the current request.
 *
 * <p>{@link AttributeSet#MINIMAL} (stage S2, the default) sends only {@code authz.decision},
 * {@code resource.owner_match} and {@code enduser.id}. {@link AttributeSet#FULL} (stage S3)
 * adds the rest of {@code shared/attribute-spec.md}.
 *
 * <p>Rules that keep the data trustworthy:
 * <ul>
 *   <li>{@code deny} always wins over {@code allow}.</li>
 *   <li>{@code resource.owner_match} is sticky: once a mismatch is seen it stays {@code false}.</li>
 *   <li>Raw identifiers are never sent; they go through {@link Pseudonymizer}.</li>
 * </ul>
 */
public class AuthzTelemetry {

    private static final String STATE = AuthzTelemetry.class.getName() + ".state";

    /** Which attributes to send. */
    public enum AttributeSet { MINIMAL, FULL }

    private final TelemetryRecorder recorder;
    private final Pseudonymizer pseudonymizer;
    private final boolean full;

    public AuthzTelemetry(TelemetryRecorder recorder, Pseudonymizer pseudonymizer, AttributeSet attributeSet) {
        this.recorder = recorder;
        this.pseudonymizer = pseudonymizer;
        this.full = attributeSet == AttributeSet.FULL;
    }

    public void requiredScope(String scope) {
        state().requiredScope = scope;
        if (full) {
            recorder.attribute(AuthzAttributes.REQUIRED_SCOPE, scope);
        }
    }

    /**
     * Marks a legitimate cross-owner access (admin / support). Always sent, even with
     * {@link AttributeSet#MINIMAL}: detection D01 needs it to exclude these accesses.
     */
    public void bypass(String scope) {
        state().requiredScope = scope;
        recorder.attribute(AuthzAttributes.REQUIRED_SCOPE, scope);
    }

    public String requiredScope() {
        return state().requiredScope;
    }

    public void grantedScopes(Collection<String> scopes) {
        if (!full || scopes == null || scopes.isEmpty()) {
            return;
        }
        recorder.attribute(AuthzAttributes.GRANTED_SCOPES,
                scopes.stream().sorted().distinct().collect(Collectors.joining(",")));
    }

    public void user(String rawUserId) {
        String id = pseudonymizer.user(rawUserId);
        if (id != null) {
            recorder.userId(id);
        }
    }

    public void apiKey(String rawApiKey) {
        String id = full ? pseudonymizer.apiKey(rawApiKey) : null;
        if (id != null) {
            recorder.attribute(AuthzAttributes.API_KEY_ID, id);
        }
    }

    public void clientType(String clientType) {
        if (full && clientType != null) {
            recorder.attribute(AuthzAttributes.CLIENT_TYPE, clientType);
        }
    }

    public void tokenAgeSeconds(long seconds) {
        if (full && seconds >= 0) {
            recorder.attribute(AuthzAttributes.TOKEN_AGE_SEC, seconds);
        }
    }

    public void allow() {
        State s = state();
        if (s.decision == null) {
            s.decision = AuthzAttributes.ALLOW;
            recorder.attribute(AuthzAttributes.DECISION, AuthzAttributes.ALLOW);
        }
    }

    /**
     * @param reason one of the {@code REASON_*} values, or {@code null} when unknown
     * @param cause  recorded as an expected error when not {@code null}
     */
    public void deny(String reason, Throwable cause) {
        State s = state();
        boolean first = !AuthzAttributes.DENY.equals(s.decision);
        s.decision = AuthzAttributes.DENY;
        recorder.attribute(AuthzAttributes.DECISION, AuthzAttributes.DENY);
        if (full && reason != null) {
            recorder.attribute(AuthzAttributes.DENY_REASON, reason);
        }
        if (cause != null && first) {
            recorder.expectedError(cause,
                    reason == null ? Map.of() : Map.of(AuthzAttributes.DENY_REASON, reason));
        }
    }

    public boolean decisionRecorded() {
        return state().decision != null;
    }

    public void ownership(String resourceType, boolean ownerMatches) {
        State s = state();
        if (full && resourceType != null && !resourceType.isBlank()) {
            recorder.attribute(AuthzAttributes.RESOURCE_TYPE, resourceType);
        }
        if (!ownerMatches) {
            s.ownerMismatch = true;
        }
        recorder.attribute(AuthzAttributes.OWNER_MATCH, !s.ownerMismatch);
    }

    private State state() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            return new State(); // outside a request: record without cross-call state
        }
        State s = (State) attrs.getAttribute(STATE, RequestAttributes.SCOPE_REQUEST);
        if (s == null) {
            s = new State();
            attrs.setAttribute(STATE, s, RequestAttributes.SCOPE_REQUEST);
        }
        return s;
    }

    private static final class State {
        String decision;
        String requiredScope;
        boolean ownerMismatch;
    }
}
