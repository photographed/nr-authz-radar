package io.github.photographed.authzradar;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.ClassUtils;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Per-request recording for every Spring MVC endpoint: the user, the required scope (from the
 * handler's annotations) and, when nothing else decided, {@code allow} after the handler ran.
 */
public class RequiredScopeInterceptor implements HandlerInterceptor {

    private static final boolean JWT_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.jwt.Jwt", RequiredScopeInterceptor.class.getClassLoader());

    private final AuthzTelemetry telemetry;
    private final ScopeExtractor scopes;
    private final ClientTypeResolver clientTypes;

    public RequiredScopeInterceptor(AuthzTelemetry telemetry, ScopeExtractor scopes, ClientTypeResolver clientTypes) {
        this.telemetry = telemetry;
        this.scopes = scopes;
        this.clientTypes = clientTypes;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if (handler instanceof HandlerMethod hm) {
            telemetry.requiredScope(scopes.extract(hm.getMethod(), hm.getBeanType()));
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            telemetry.user(auth.getName());
            telemetry.grantedScopes(grantedScopes(auth));
            if (JWT_PRESENT) {
                JwtSupport.tokenAge(auth).ifPresent(telemetry::tokenAgeSeconds);
            }
        }
        telemetry.clientType(clientTypes.resolve(request, auth));
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (telemetry.decisionRecorded()) {
            return;
        }
        if (ex instanceof AccessDeniedException) {
            telemetry.deny(null, null); // reason unknown here; the security events add it when they can
        } else if (ex == null && response.getStatus() < 400) {
            telemetry.allow();
        } else if (response.getStatus() == 401) {
            telemetry.deny(AuthzAttributes.REASON_UNAUTHENTICATED, null);
        } else if (response.getStatus() == 403) {
            telemetry.deny(null, null);
        }
    }

    private static List<String> grantedScopes(Authentication auth) {
        return auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a != null && a.startsWith("SCOPE_"))
                .map(a -> a.substring("SCOPE_".length()))
                .toList();
    }

    /** Isolated so the class loads without spring-security-oauth2-jose on the classpath. */
    private static final class JwtSupport {
        static java.util.Optional<Long> tokenAge(Authentication auth) {
            if (auth.getPrincipal() instanceof org.springframework.security.oauth2.jwt.Jwt jwt
                    && jwt.getIssuedAt() != null) {
                return java.util.Optional.of(Duration.between(jwt.getIssuedAt(), Instant.now()).getSeconds());
            }
            return java.util.Optional.empty();
        }
    }
}
