package io.github.photographed.authzradar;

import java.util.Collection;
import java.util.Map;
import java.util.TreeSet;
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
 *   <li>{@code deny} always wins over {@code allow}; the first known deny reason wins.</li>
 *   <li>{@code resource.owner_match} is sticky: once a mismatch is seen it stays {@code false}.</li>
 *   <li>Raw identifiers are never sent; they go through {@link Pseudonymizer}.</li>
 * </ul>
 */
public class AuthzTelemetry {

    private static final String STATE = AuthzTelemetry.class.getName() + ".state";
    private static final int MAX_OPERATIONS = 3;

    /** State for work outside an HTTP request (WebSocket messages, GraphQL over WebSocket). */
    private static final ThreadLocal<State> SCOPED = new ThreadLocal<>();

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
        // The first known reason wins: an outer handler seeing the same exception must not
        // overwrite "owner_mismatch" with a guess.
        if (reason != null && s.denyReason == null) {
            s.denyReason = reason;
            if (full) {
                recorder.attribute(AuthzAttributes.DENY_REASON, reason);
            }
        }
        if (cause != null && first) {
            recorder.expectedError(cause,
                    reason == null ? Map.of() : Map.of(AuthzAttributes.DENY_REASON, reason));
        }
    }

    /**
     * Opens a per-thread scope for work that has no HTTP request (e.g. a WebSocket message), so
     * "deny wins" and the sticky owner_match still hold across calls. Nested scopes reuse the outer one.
     */
    public Scope scope() {
        if (RequestContextHolder.getRequestAttributes() != null || SCOPED.get() != null) {
            return () -> { };
        }
        SCOPED.set(new State());
        return SCOPED::remove;
    }

    /** Closing a scope never throws. */
    public interface Scope extends AutoCloseable {
        @Override
        void close();
    }

    public void transactionName(String category, String name) {
        recorder.transactionName(category, name);
    }

    /**
     * Records {@code api.protocol} and {@code api.operation} (shared/protocols.md). Sent in MINIMAL
     * too: without them the status-code based detections cannot be interpreted for non-REST APIs.
     * Several operations in one request (GraphQL) are joined, sorted, up to three.
     */
    public void protocol(String protocol, String operation) {
        State s = state();
        recorder.attribute(AuthzAttributes.PROTOCOL, protocol);
        if (operation == null || operation.isBlank()) {
            return;
        }
        s.operations.add(operation);
        String joined = s.operations.stream().limit(MAX_OPERATIONS).collect(Collectors.joining(","));
        recorder.attribute(AuthzAttributes.OPERATION, s.operations.size() > MAX_OPERATIONS ? joined + ",…" : joined);
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
        s.checkCount++;
        recorder.attribute(AuthzAttributes.OWNER_MATCH, !s.ownerMismatch);
        if (full) {
            recorder.attribute(AuthzAttributes.CHECK_COUNT, s.checkCount);
        }
    }

    private State state() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            State scoped = SCOPED.get();
            return scoped != null ? scoped : new State(); // no request and no scope: no cross-call state
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
        String denyReason;
        int checkCount;
        final TreeSet<String> operations = new TreeSet<>();
    }
}
