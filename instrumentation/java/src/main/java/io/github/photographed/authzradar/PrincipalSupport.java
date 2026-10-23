package io.github.photographed.authzradar;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/** Shared by the non-HTTP aspects: who is calling, and why a denial happened. */
public class PrincipalSupport {

    private final AuthzTelemetry telemetry;

    public PrincipalSupport(AuthzTelemetry telemetry) {
        this.telemetry = telemetry;
    }

    public void recordUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (authenticated(auth)) {
            telemetry.user(auth.getName());
        }
    }

    public String denyReason() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (!authenticated(auth)) {
            return AuthzAttributes.REASON_UNAUTHENTICATED;
        }
        String required = telemetry.requiredScope();
        return required != null && required.startsWith("role:")
                ? AuthzAttributes.REASON_ROLE_MISSING : AuthzAttributes.REASON_SCOPE_MISSING;
    }

    private static boolean authenticated(Authentication auth) {
        return auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken);
    }
}
