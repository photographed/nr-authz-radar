package io.github.photographed.authzradar;

import java.lang.reflect.Method;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.graphql.data.method.annotation.MutationMapping;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.graphql.data.method.annotation.SchemaMapping;
import org.springframework.graphql.data.method.annotation.SubscriptionMapping;
import org.springframework.security.access.AccessDeniedException;

/**
 * Spring for GraphQL resolvers: records {@code api.protocol = graphql} and the server-side
 * operation ({@code Query.order}), never the client-chosen operation name, which can be spoofed.
 * Runs outside method security so denials by {@code @PreAuthorize} on resolvers are recorded.
 */
@Aspect
public class GraphQlAspect implements Ordered {

    private final AuthzTelemetry telemetry;
    private final ScopeExtractor scopes;
    private final PrincipalSupport principals;

    public GraphQlAspect(AuthzTelemetry telemetry, ScopeExtractor scopes, PrincipalSupport principals) {
        this.telemetry = telemetry;
        this.scopes = scopes;
        this.principals = principals;
    }

    @Around("@annotation(org.springframework.graphql.data.method.annotation.QueryMapping)"
            + " || @annotation(org.springframework.graphql.data.method.annotation.MutationMapping)"
            + " || @annotation(org.springframework.graphql.data.method.annotation.SubscriptionMapping)"
            + " || @annotation(org.springframework.graphql.data.method.annotation.SchemaMapping)")
    public Object around(ProceedingJoinPoint pjp) throws Throwable {
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        Class<?> type = pjp.getTarget() != null ? pjp.getTarget().getClass() : method.getDeclaringClass();
        try (AuthzTelemetry.Scope ignored = telemetry.scope()) {
            String operation = operation(method);
            telemetry.protocol("graphql", operation);
            if (operation.startsWith("Query.") || operation.startsWith("Mutation.") || operation.startsWith("Subscription.")) {
                telemetry.requiredScope(scopes.extract(method, type));
            }
            principals.recordUser();
            try {
                Object result = pjp.proceed();
                telemetry.allow();
                return result;
            } catch (AccessDeniedException e) {
                telemetry.deny(principals.denyReason(), e);
                throw e;
            }
        }
    }

    static String operation(Method method) {
        String field = method.getName();
        QueryMapping q = AnnotatedElementUtils.findMergedAnnotation(method, QueryMapping.class);
        if (q != null) {
            return "Query." + first(q.name(), q.value(), field);
        }
        MutationMapping m = AnnotatedElementUtils.findMergedAnnotation(method, MutationMapping.class);
        if (m != null) {
            return "Mutation." + first(m.name(), m.value(), field);
        }
        SubscriptionMapping s = AnnotatedElementUtils.findMergedAnnotation(method, SubscriptionMapping.class);
        if (s != null) {
            return "Subscription." + first(s.name(), s.value(), field);
        }
        SchemaMapping sm = AnnotatedElementUtils.findMergedAnnotation(method, SchemaMapping.class);
        SchemaMapping onClass = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), SchemaMapping.class);
        String typeName = sm != null && !sm.typeName().isBlank() ? sm.typeName()
                : onClass != null && !onClass.typeName().isBlank() ? onClass.typeName() : "?";
        return typeName + "." + (sm == null ? field : first(sm.field(), sm.value(), field));
    }

    private static String first(String a, String b, String fallback) {
        return !a.isBlank() ? a : !b.isBlank() ? b : fallback;
    }

    /** Outside method security, so a resolver denied by {@code @PreAuthorize} is still recorded. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
