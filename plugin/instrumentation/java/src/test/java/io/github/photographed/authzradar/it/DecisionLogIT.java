package io.github.photographed.authzradar.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.photographed.authzradar.InMemoryDecisionLog;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

/** log-decisions: one structured line for denials and allowed mismatches, none for normal allows. */
@SpringBootTest(classes = TestApp.class, properties = {
        "nr.authz-radar.log-decisions=true",
        "nr.authz-radar.hmac-key=test-only-key",
        "nr.authz-radar.bypass-authorities=SCOPE_admin:read"})
class DecisionLogIT {

    @Autowired WebApplicationContext context;
    @Autowired InMemoryDecisionLog log;
    MockMvc mvc;

    @BeforeEach
    void reset() {
        mvc = MockMvcSupport.mockMvc(context);
        log.lines.clear();
    }

    @Test
    void normalAllowWritesNothing() throws Exception {
        mvc.perform(get("/api/orders/1").with(user("alice").authorities(() -> "SCOPE_orders:read"))).andExpect(status().isOk());
        assertThat(log.lines).isEmpty();
    }

    @Test
    void denialWritesOneLineWithTheReason() throws Exception {
        mvc.perform(get("/api/orders/2").with(user("alice").authorities(() -> "SCOPE_orders:read"))).andExpect(status().isForbidden());
        assertThat(log.lines).containsExactly(
                "authz-radar decision=deny owner_match=false reason=owner_mismatch resource.type=order api.operation=-");
    }

    @Test
    void observedMismatchWritesTheD01Line() throws Exception {
        mvc.perform(get("/api/observe/orders/2").with(user("alice").authorities(() -> "SCOPE_orders:read"))).andExpect(status().isOk());
        assertThat(log.lines).singleElement().asString().startsWith("authz-radar decision=allow owner_match=false");
    }

    @Test
    void bypassIsMarkedAndNoUserIdIsLogged() throws Exception {
        mvc.perform(get("/api/orders/2").with(user("ops").authorities(() -> "SCOPE_orders:read", () -> "SCOPE_admin:read")))
                .andExpect(status().isOk());
        assertThat(log.lines).singleElement().asString().endsWith("bypass=admin:read").doesNotContain("ops");
    }
}
