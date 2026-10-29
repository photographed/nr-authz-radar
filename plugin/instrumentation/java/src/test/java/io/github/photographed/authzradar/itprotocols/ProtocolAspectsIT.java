package io.github.photographed.authzradar.itprotocols;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.newrelic.api.agent.Trace;
import io.github.photographed.authzradar.AuthzTelemetry;
import io.github.photographed.authzradar.InMemoryRecorder;
import io.github.photographed.authzradar.StompAspect;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

@SpringBootTest(classes = ProtocolApp.class, webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "nr.authz-radar.attributes=FULL",
        "nr.authz-radar.hmac-key=test-only-key"})
class ProtocolAspectsIT {

    @Autowired ProtocolApp.OrderGraphQl graphql;
    @Autowired ProtocolApp.OrderStomp stomp;
    @Autowired AuthzTelemetry telemetry;
    @Autowired InMemoryRecorder nr;

    @BeforeEach
    void reset() {
        nr.reset();
    }

    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    private static void login(String user, String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(UsernamePasswordAuthenticationToken.authenticated(
                user, "n/a", AuthorityUtils.createAuthorityList(authorities)));
    }

    @Test
    void graphQlRecordsTheServerSideOperation() {
        login("alice", "SCOPE_orders:read");
        graphql.order(1L);
        assertThat(nr.attributes)
                .containsEntry("api.protocol", "graphql")
                .containsEntry("api.operation", "Query.order")
                .containsEntry("authz.required_scope", "orders:read")
                .containsEntry("authz.decision", "allow")
                .containsEntry("resource.owner_match", true);
        assertThat(nr.userId).startsWith("u_");
    }

    @Test
    void graphQlOwnershipDenialKeepsItsReason() {
        login("alice", "SCOPE_orders:read");
        assertThatThrownBy(() -> graphql.order(2L)).isInstanceOf(AccessDeniedException.class);
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "owner_mismatch")
                .containsEntry("resource.owner_match", false);
        assertThat(nr.expectedErrors).hasSize(1);
    }

    @Test
    void graphQlResolverDeniedByPreAuthorizeIsRecorded() {
        login("alice", "SCOPE_profile");
        assertThatThrownBy(() -> graphql.order(1L)).isInstanceOf(AccessDeniedException.class);
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "scope_missing")
                .doesNotContainKey("resource.owner_match");
    }

    @Test
    void severalFieldsInOneRequestAreJoinedAndChecksCounted() {
        login("alice", "SCOPE_orders:read");
        try (AuthzTelemetry.Scope ignored = telemetry.scope()) {
            graphql.health();
            graphql.order(1L);
            graphql.order(1L);
            graphql.order(1L);
        }
        assertThat(nr.attributes)
                .containsEntry("api.operation", "Query.health,Query.order")
                .containsEntry("resource.check_count", 3);
    }

    @Test
    void enumerationInOneRequestStaysVisible() {
        login("alice", "SCOPE_orders:read");
        try (AuthzTelemetry.Scope ignored = telemetry.scope()) {
            graphql.order(1L);
            assertThatThrownBy(() -> graphql.order(2L)).isInstanceOf(AccessDeniedException.class);
            graphql.order(1L); // a later match must not hide the mismatch, nor turn deny into allow
        }
        assertThat(nr.attributes)
                .containsEntry("resource.owner_match", false)
                .containsEntry("authz.decision", "deny");
    }

    @Test
    void stompMessageGetsItsOwnTransaction() {
        login("alice", "SCOPE_orders:read");
        stomp.get(1L);
        assertThat(nr.transactionName).isEqualTo("WebSocket/SEND orders.get");
        assertThat(nr.attributes)
                .containsEntry("api.protocol", "websocket")
                .containsEntry("api.operation", "SEND orders.get")
                .containsEntry("authz.decision", "allow")
                .containsEntry("resource.owner_match", true);
    }

    @Test
    void subscribingToSomeoneElsesTopicIsDenied() {
        login("alice");
        assertThatThrownBy(() -> stomp.subscribe(2L)).isInstanceOf(AccessDeniedException.class);
        assertThat(nr.transactionName).isEqualTo("WebSocket/SUBSCRIBE /topic/orders/{id}");
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "owner_mismatch")
                .containsEntry("resource.owner_match", false);
    }

    @Test
    void stompAdviceStartsATransactionForTheAgent() {
        Trace trace = Arrays.stream(StompAspect.class.getMethods())
                .filter(m -> m.getName().equals("around")).findFirst().orElseThrow()
                .getAnnotation(Trace.class);
        assertThat(trace).isNotNull();
        assertThat(trace.dispatcher()).isTrue();
    }
}
