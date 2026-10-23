package io.github.photographed.authzradar;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@ConditionalOnClass({com.newrelic.api.agent.NewRelic.class, Authentication.class})
@ConditionalOnProperty(prefix = "nr.authz-radar", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AuthzRadarProperties.class)
public class AuthzRadarAutoConfiguration {

    private static final Log log = LogFactory.getLog(AuthzRadarAutoConfiguration.class);

    @Bean
    @ConditionalOnMissingBean
    public TelemetryRecorder authzRadarRecorder() {
        return new NewRelicRecorder();
    }

    @Bean
    @ConditionalOnMissingBean
    public AuthzTelemetry authzTelemetry(TelemetryRecorder recorder, AuthzRadarProperties props) {
        Pseudonymizer pseudonymizer = new Pseudonymizer(props.getHmacKey());
        if (!pseudonymizer.enabled()) {
            log.warn("nr.authz-radar.hmac-key is not set: enduser.id and api.key_id will not be sent");
        }
        return new AuthzTelemetry(recorder, pseudonymizer, props.getAttributes());
    }

    @Bean
    @ConditionalOnMissingBean
    public ClientTypeResolver authzRadarClientTypeResolver() {
        return (request, authentication) -> null;
    }

    @Bean
    public AuthzEventsListener authzEventsListener(AuthzTelemetry telemetry) {
        return new AuthzEventsListener(telemetry);
    }

    /**
     * Method security ({@code @PreAuthorize}) publishes denial events only when such a bean
     * exists. URL rules publish them regardless (verified with Spring Security 6.5).
     */
    @Bean
    @ConditionalOnMissingBean(AuthorizationEventPublisher.class)
    public AuthorizationEventPublisher authzRadarAuthorizationEventPublisher(ApplicationEventPublisher publisher) {
        return new SpringAuthorizationEventPublisher(publisher);
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.aspectj.lang.annotation.Aspect")
    static class Ownership {
        @Bean
        public OwnershipAspect authzRadarOwnershipAspect(AuthzTelemetry telemetry, AuthzRadarProperties props) {
            return new OwnershipAspect(telemetry, props.getOwnershipMode(), props.getBypassAuthorities());
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.aspectj.lang.annotation.Aspect",
            "org.springframework.graphql.data.method.annotation.QueryMapping"})
    static class GraphQl {
        @Bean
        public GraphQlAspect authzRadarGraphQlAspect(AuthzTelemetry telemetry) {
            return new GraphQlAspect(telemetry, new ScopeExtractor(), new PrincipalSupport(telemetry));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.aspectj.lang.annotation.Aspect",
            "org.springframework.messaging.handler.annotation.MessageMapping"})
    static class Stomp {
        @Bean
        public StompAspect authzRadarStompAspect(AuthzTelemetry telemetry) {
            return new StompAspect(telemetry, new ScopeExtractor(), new PrincipalSupport(telemetry));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(WebMvcConfigurer.class)
    static class WebMvc implements WebMvcConfigurer {
        private final RequiredScopeInterceptor interceptor;

        WebMvc(AuthzTelemetry telemetry, ClientTypeResolver clientTypes) {
            this.interceptor = new RequiredScopeInterceptor(telemetry, new ScopeExtractor(), clientTypes);
        }

        @Override
        public void addInterceptors(InterceptorRegistry registry) {
            registry.addInterceptor(interceptor);
        }
    }
}
