package io.github.photographed.authzradar.it;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.photographed.authzradar.InMemoryRecorder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.context.WebApplicationContext;

/** Default settings, no HMAC key: stage S2 attributes only, and no user ID at all. */
@SpringBootTest(classes = TestApp.class)
class MinimalAttributesIT {

    @Autowired WebApplicationContext context;
    @Autowired InMemoryRecorder nr;
    MockMvc mvc;

    @BeforeEach
    void reset() {
        mvc = MockMvcSupport.mockMvc(context);
        nr.reset();
    }

    @Test
    void sendsOnlyTheTwoStageS2Attributes() throws Exception {
        mvc.perform(get("/api/orders/2").with(user("alice").authorities(() -> "SCOPE_orders:read")))
                .andExpect(status().isForbidden());
        assertThat(nr.attributes).containsOnlyKeys("authz.decision", "resource.owner_match");
        assertThat(nr.attributes)
                .containsEntry("authz.decision", "deny")
                .containsEntry("resource.owner_match", false);
        assertThat(nr.expectedErrors).hasSize(1);
    }

    @Test
    void withoutHmacKeyNoUserIdIsSent() throws Exception {
        mvc.perform(get("/api/orders/1").with(user("alice").authorities(() -> "SCOPE_orders:read")))
                .andExpect(status().isOk());
        assertThat(nr.userId).isNull();
        assertThat(nr.attributes).containsEntry("authz.decision", "allow");
    }
}
