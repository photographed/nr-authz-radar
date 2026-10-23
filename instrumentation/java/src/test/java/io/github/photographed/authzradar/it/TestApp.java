package io.github.photographed.authzradar.it;

import io.github.photographed.authzradar.CheckOwnership;
import io.github.photographed.authzradar.InMemoryRecorder;
import io.github.photographed.authzradar.Owned;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/** Order 1 belongs to alice, every other order to bob. */
@SpringBootApplication
@EnableMethodSecurity
public class TestApp {

    public record Order(Long id, String ownerId) implements Owned { }

    @Service
    public static class OrderService {
        @CheckOwnership(type = "order")
        public Order find(Long id) {
            return new Order(id, id == 1 ? "alice" : "bob");
        }

        @CheckOwnership(type = "order", mode = CheckOwnership.OwnershipMode.OBSERVE)
        public Order findObserved(Long id) {
            return new Order(id, id == 1 ? "alice" : "bob");
        }
    }

    @RestController
    public static class OrderController {
        private final OrderService service;

        OrderController(OrderService service) {
            this.service = service;
        }

        @GetMapping("/api/orders/{id}")
        @PreAuthorize("hasAuthority('SCOPE_orders:read')")
        public Order get(@PathVariable Long id) {
            return service.find(id);
        }

        @GetMapping("/api/observe/orders/{id}")
        @PreAuthorize("hasAuthority('SCOPE_orders:read')")
        public Order observe(@PathVariable Long id) {
            return service.findObserved(id);
        }
    }

    @Bean
    InMemoryRecorder recorder() {
        return new InMemoryRecorder();
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated())
                .httpBasic(Customizer.withDefaults())
                .csrf(c -> c.disable());
        return http.build();
    }
}
