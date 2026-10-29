package io.github.photographed.authzradar.it;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Builds MockMvc with spring-test + spring-security-test only, so the same tests run on
 * Spring Boot 3.x and 4.x (@AutoConfigureMockMvc moved to another module in Boot 4).
 */
final class MockMvcSupport {

    private MockMvcSupport() {
    }

    static MockMvc mockMvc(WebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }
}
