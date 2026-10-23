package io.github.photographed.authzradar;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Derives {@code authz.required_scope} from {@code @PreAuthorize} / {@code @Secured} on the
 * handler method (falling back to its class). One interceptor covers every endpoint.
 */
public class ScopeExtractor {

    private static final Pattern SCOPE = Pattern.compile("SCOPE_([A-Za-z0-9:._/\\-]+)");
    private static final Pattern ROLE_CALL = Pattern.compile("has(?:Any)?Role\\(([^)]*)\\)");
    private static final Pattern QUOTED = Pattern.compile("'([^']+)'");

    public String extract(Method method, Class<?> beanType) {
        String fromMethod = fromElement(method);
        if (fromMethod != null) {
            return fromMethod;
        }
        String fromClass = fromElement(beanType);
        return fromClass != null ? fromClass : AuthzAttributes.SCOPE_NONE;
    }

    private String fromElement(java.lang.reflect.AnnotatedElement element) {
        if (element == null) {
            return null;
        }
        PreAuthorize pre = AnnotatedElementUtils.findMergedAnnotation(element, PreAuthorize.class);
        if (pre != null) {
            return fromExpression(pre.value());
        }
        Secured secured = AnnotatedElementUtils.findMergedAnnotation(element, Secured.class);
        if (secured != null) {
            return fromAuthorities(Arrays.asList(secured.value()));
        }
        return null;
    }

    String fromExpression(String expression) {
        TreeSet<String> out = new TreeSet<>();
        Matcher scope = SCOPE.matcher(expression);
        while (scope.find()) {
            out.add(scope.group(1));
        }
        Matcher role = ROLE_CALL.matcher(expression);
        while (role.find()) {
            Matcher q = QUOTED.matcher(role.group(1));
            while (q.find()) {
                out.add("role:" + q.group(1).replaceFirst("^ROLE_", ""));
            }
        }
        // An expression we cannot read (e.g. a custom bean check) is still a check: say so.
        return out.isEmpty() ? "custom" : String.join(",", out);
    }

    private String fromAuthorities(Collection<String> authorities) {
        TreeSet<String> out = new TreeSet<>();
        for (String a : authorities) {
            if (a.startsWith("SCOPE_")) {
                out.add(a.substring("SCOPE_".length()));
            } else {
                out.add("role:" + a.replaceFirst("^ROLE_", ""));
            }
        }
        return out.isEmpty() ? AuthzAttributes.SCOPE_NONE : String.join(",", out);
    }
}
