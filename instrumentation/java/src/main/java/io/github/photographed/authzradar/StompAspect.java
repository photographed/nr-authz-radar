package io.github.photographed.authzradar;

import com.newrelic.api.agent.Trace;
import java.lang.reflect.Method;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.security.access.AccessDeniedException;

/**
 * WebSocket / STOMP handlers ({@code @MessageMapping}, {@code @SubscribeMapping}).
 *
 * <p>The New Relic Java agent does not instrument WebSocket messages, so attributes recorded while
 * handling a message would be dropped. {@code @Trace(dispatcher = true)} on the advice makes the
 * agent start a transaction for every message, named {@code WebSocket / SEND <destination>} or
 * {@code SUBSCRIBE <destination>}.
 */
@Aspect
public class StompAspect implements Ordered {

    private final AuthzTelemetry telemetry;
    private final ScopeExtractor scopes;
    private final PrincipalSupport principals;

    public StompAspect(AuthzTelemetry telemetry, ScopeExtractor scopes, PrincipalSupport principals) {
        this.telemetry = telemetry;
        this.scopes = scopes;
        this.principals = principals;
    }

    @Trace(dispatcher = true)
    @Around("@annotation(org.springframework.messaging.handler.annotation.MessageMapping)"
            + " || @annotation(org.springframework.messaging.simp.annotation.SubscribeMapping)")
    public Object around(ProceedingJoinPoint pjp) throws Throwable {
        Method method = ((MethodSignature) pjp.getSignature()).getMethod();
        Class<?> type = pjp.getTarget() != null ? pjp.getTarget().getClass() : method.getDeclaringClass();
        String operation = operation(method);
        try (AuthzTelemetry.Scope ignored = telemetry.scope()) {
            telemetry.transactionName("WebSocket", operation);
            telemetry.protocol("websocket", operation);
            telemetry.requiredScope(scopes.extract(method, type));
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
        SubscribeMapping sub = AnnotatedElementUtils.findMergedAnnotation(method, SubscribeMapping.class);
        if (sub != null) {
            return "SUBSCRIBE " + destination(sub.value(), method);
        }
        MessageMapping msg = AnnotatedElementUtils.findMergedAnnotation(method, MessageMapping.class);
        MessageMapping onClass = AnnotatedElementUtils.findMergedAnnotation(method.getDeclaringClass(), MessageMapping.class);
        String prefix = onClass != null && onClass.value().length > 0 ? onClass.value()[0] : "";
        return "SEND " + prefix + destination(msg == null ? new String[0] : msg.value(), method);
    }

    private static String destination(String[] values, Method method) {
        return values.length > 0 ? values[0] : method.getName();
    }

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
