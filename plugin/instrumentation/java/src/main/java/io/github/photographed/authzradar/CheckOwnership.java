package io.github.photographed.authzradar;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Compares the owner of the returned resource(s) with the current principal and records
 * {@code resource.owner_match}. Put it on the data-access method (service / repository) that
 * loads a resource by an ID supplied by the client: that is where IDOR happens.
 *
 * <p>Supported return types: {@link Owned}, {@code Optional<? extends Owned>},
 * {@code Iterable<? extends Owned>}. Other values are ignored.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface CheckOwnership {

    /** Resource type for {@code resource.type}, e.g. {@code "order"}. */
    String type() default "";

    /** Overrides {@code nr.authz-radar.ownership-mode} for this method. */
    OwnershipMode mode() default OwnershipMode.DEFAULT;

    enum OwnershipMode {
        /** Use the configured mode. */
        DEFAULT,
        /** Deny on mismatch (throws {@code AccessDeniedException}). */
        ENFORCE,
        /**
         * Record only. Mismatches are let through and show up as
         * {@code owner_match = false AND decision = 'allow'} (detection D01): use this to find
         * real IDOR occurrences before switching to {@link #ENFORCE}.
         */
        OBSERVE
    }
}
