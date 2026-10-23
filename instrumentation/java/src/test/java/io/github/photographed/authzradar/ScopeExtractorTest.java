package io.github.photographed.authzradar;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;

class ScopeExtractorTest {

    private final ScopeExtractor extractor = new ScopeExtractor();

    @PreAuthorize("hasRole('ADMIN')")
    static class AdminController {
        @PreAuthorize("hasAuthority('SCOPE_orders:read')") public void read() { }
        @PreAuthorize("hasAnyAuthority('SCOPE_orders:write', 'SCOPE_admin')") public void write() { }
        @PreAuthorize("@guard.check(#id)") public void custom() { }
        @Secured({"ROLE_SUPPORT", "SCOPE_tickets:read"}) public void secured() { }
        public void inherited() { }
    }

    static class OpenController {
        public void open() { }
    }

    private String scopeOf(Class<?> type, String method) throws Exception {
        return extractor.extract(type.getMethod(method), type);
    }

    @Test
    void readsScopesRolesAndFallsBackToClass() throws Exception {
        assertThat(scopeOf(AdminController.class, "read")).isEqualTo("orders:read");
        assertThat(scopeOf(AdminController.class, "write")).isEqualTo("admin,orders:write");
        assertThat(scopeOf(AdminController.class, "custom")).isEqualTo("custom");
        assertThat(scopeOf(AdminController.class, "secured")).isEqualTo("role:SUPPORT,tickets:read");
        assertThat(scopeOf(AdminController.class, "inherited")).isEqualTo("role:ADMIN");
    }

    @Test
    void noAnnotationMeansNone() throws Exception {
        assertThat(scopeOf(OpenController.class, "open")).isEqualTo(AuthzAttributes.SCOPE_NONE);
    }
}
