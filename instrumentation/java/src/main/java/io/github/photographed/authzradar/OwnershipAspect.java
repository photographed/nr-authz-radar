package io.github.photographed.authzradar;

import java.util.Collection;
import java.util.Optional;
import java.util.Set;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/** Implements {@link CheckOwnership}. */
@Aspect
public class OwnershipAspect {

    private final AuthzTelemetry telemetry;
    private final CheckOwnership.OwnershipMode defaultMode;
    private final Set<String> bypassAuthorities;

    public OwnershipAspect(AuthzTelemetry telemetry, CheckOwnership.OwnershipMode defaultMode,
                           Collection<String> bypassAuthorities) {
        this.telemetry = telemetry;
        this.defaultMode = defaultMode == CheckOwnership.OwnershipMode.DEFAULT
                ? CheckOwnership.OwnershipMode.ENFORCE : defaultMode;
        this.bypassAuthorities = Set.copyOf(bypassAuthorities);
    }

    @Around("@annotation(check)")
    public Object around(ProceedingJoinPoint pjp, CheckOwnership check) throws Throwable {
        Object result = pjp.proceed();
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String current = (auth == null || auth instanceof AnonymousAuthenticationToken) ? null : auth.getName();
        CheckOwnership.OwnershipMode mode =
                check.mode() == CheckOwnership.OwnershipMode.DEFAULT ? defaultMode : check.mode();

        for (Owned owned : owned(result)) {
            boolean match = current != null && current.equals(owned.ownerId());
            telemetry.ownership(check.type(), match);
            if (match) {
                continue;
            }
            String bypass = bypassAuthority(auth);
            if (bypass != null) {
                // Legitimate cross-owner access (admin / support): label it so D01 can exclude it.
                String scope = bypass.replaceFirst("^SCOPE_", "");
                telemetry.bypass(scope);
                telemetry.mismatchLetThrough(scope);
                continue;
            }
            if (mode == CheckOwnership.OwnershipMode.ENFORCE) {
                AccessDeniedException denied = new AccessDeniedException("ownership check failed");
                telemetry.deny(AuthzAttributes.REASON_OWNER_MISMATCH, denied);
                throw denied;
            }
            telemetry.mismatchLetThrough(null);   // OBSERVE: the D01 case
        }
        return result;
    }

    private String bypassAuthority(Authentication auth) {
        if (auth == null || bypassAuthorities.isEmpty()) {
            return null;
        }
        for (GrantedAuthority a : auth.getAuthorities()) {
            if (bypassAuthorities.contains(a.getAuthority())) {
                return a.getAuthority();
            }
        }
        return null;
    }

    private static Iterable<Owned> owned(Object value) {
        if (value instanceof Owned o) {
            return java.util.List.of(o);
        }
        if (value instanceof Optional<?> opt) {
            return opt.filter(Owned.class::isInstance).map(Owned.class::cast).stream().toList();
        }
        if (value instanceof Iterable<?> items) {
            java.util.List<Owned> out = new java.util.ArrayList<>();
            for (Object item : items) {
                if (item instanceof Owned o) {
                    out.add(o);
                }
            }
            return out;
        }
        return java.util.List.of();
    }
}
