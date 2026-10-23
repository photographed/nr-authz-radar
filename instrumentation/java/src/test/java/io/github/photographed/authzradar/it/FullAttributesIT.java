package io.github.photographed.authzradar.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.photographed.authzradar.InMemoryRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = TestApp.class, properties = {
        "nr.authz-radar.attributes=FULL",
        "nr.authz-radar.hmac-key=test-only-key",
        "nr.authz-radar.bypass-authorities=SCOPE_admin:read"})
@AutoConfigureMockMvc
class FullAttributesIT {

    @Autowired MockMvc mvc;
    @Autowired InMemoryRecorder nr;

    @BeforeEach
    void reset() {
        nr.reset();
    }

    @Test
    void ownerReadingOwnOrderIsAllowed() throws Exception {
        mvc.perform(get("/api/orders/1").with(user("alice").authorities(() -> "SCOPE_orders:read")))
                .andExpect(status().isOk());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "allow")
                .containsEntry("resource.owner_match", true)
                .containsEntry("resource.type", "order")
                .containsEntry("authz.required_scope", "orders:read")
                .containsEntry("authz.granted_scopes", "orders:read");
        assertThat(nr.userId).startsWith("u_").doesNotContain("alice");
        assertThat(nr.expectedErrors).isEmpty();
    }

    @Test
    void readingSomeoneElsesOrderIsDeniedAndRecorded() throws Exception {
        mvc.perform(get("/api/orders/2").with(user("alice").authorities(() -> "SCOPE_orders:read")))
                .andExpect(status().isForbidden());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "owner_mismatch")
                .containsEntry("resource.owner_match", false);
        assertThat(nr.expectedErrors).hasSize(1);
    }

    @Test
    void missingScopeIsDeniedBeforeTheHandler() throws Exception {
        mvc.perform(get("/api/orders/1").with(user("alice").authorities(() -> "SCOPE_profile")))
                .andExpect(status().isForbidden());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "scope_missing")
                .doesNotContainKey("resource.owner_match");
    }

    @Test
    void observeModeLetsTheMismatchThroughSoD01CanSeeIt() throws Exception {
        mvc.perform(get("/api/observe/orders/2").with(user("alice").authorities(() -> "SCOPE_orders:read")))
                .andExpect(status().isOk());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "allow")
                .containsEntry("resource.owner_match", false);
    }

    @Test
    void adminBypassIsLabelledSoD01CanExcludeIt() throws Exception {
        mvc.perform(get("/api/orders/2")
                        .with(user("ops").authorities(() -> "SCOPE_orders:read", () -> "SCOPE_admin:read")))
                .andExpect(status().isOk());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "allow")
                .containsEntry("resource.owner_match", false)
                .containsEntry("authz.required_scope", "admin:read");
    }

    @Test
    void anonymousRequestIsRecordedAsUnauthenticated() throws Exception {
        mvc.perform(get("/api/orders/1")).andExpect(status().isUnauthorized());
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("authz.deny_reason", "unauthenticated");
        assertThat(nr.userId).isNull();
    }
}
