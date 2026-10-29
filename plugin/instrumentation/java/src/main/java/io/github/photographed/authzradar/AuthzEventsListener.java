package io.github.photographed.authzradar;

import org.springframework.context.event.EventListener;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.core.Authentication;

/**
 * Records denials raised by Spring Security itself: URL rules ({@code requestMatchers}) and
 * method security ({@code @PreAuthorize}). Method security needs an
 * {@code AuthorizationEventPublisher} bean, which the auto-configuration provides when the
 * application has none.
 */
public class AuthzEventsListener {

    private final AuthzTelemetry telemetry;

    public AuthzEventsListener(AuthzTelemetry telemetry) {
        this.telemetry = telemetry;
    }

    @EventListener
    public void onDenied(AuthorizationDeniedEvent<?> event) {
        Authentication auth = event.getAuthentication().get();
        String reason;
        if (auth == null || auth instanceof AnonymousAuthenticationToken || !auth.isAuthenticated()) {
            reason = AuthzAttributes.REASON_UNAUTHENTICATED;
        } else {
            String required = telemetry.requiredScope();
            reason = required != null && required.startsWith("role:")
                    ? AuthzAttributes.REASON_ROLE_MISSING : AuthzAttributes.REASON_SCOPE_MISSING;
        }
        telemetry.deny(reason, new AccessDeniedException("authorization denied: " + reason));
    }

    @EventListener
    public void onAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        telemetry.deny(AuthzAttributes.REASON_UNAUTHENTICATED, null);
    }
}
