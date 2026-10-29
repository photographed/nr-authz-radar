package io.github.photographed.authzradar.itprotocols;

import io.github.photographed.authzradar.CheckOwnership;
import io.github.photographed.authzradar.InMemoryRecorder;
import io.github.photographed.authzradar.Owned;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.messaging.handler.annotation.DestinationVariable;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.simp.annotation.SubscribeMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;

/** GraphQL resolvers and STOMP handlers, called directly (no HTTP request). Order 1 is alice's. */
@SpringBootApplication
@EnableMethodSecurity
public class ProtocolApp {

    public record Order(Long id, String ownerId) implements Owned { }

    @Service
    public static class OrderService {
        @CheckOwnership(type = "order")
        public Order find(Long id) {
            return new Order(id, id == 1 ? "alice" : "bob");
        }
    }

    @Controller
    public static class OrderGraphQl {
        private final OrderService service;

        OrderGraphQl(OrderService service) {
            this.service = service;
        }

        @QueryMapping
        @PreAuthorize("hasAuthority('SCOPE_orders:read')")
        public Order order(@Argument Long id) {
            return service.find(id);
        }

        @QueryMapping
        public String health() {
            return "ok";
        }
    }

    @Controller
    public static class OrderStomp {
        private final OrderService service;

        OrderStomp(OrderService service) {
            this.service = service;
        }

        @MessageMapping("orders.get")
        @PreAuthorize("hasAuthority('SCOPE_orders:read')")
        public Order get(Long id) {
            return service.find(id);
        }

        @SubscribeMapping("/topic/orders/{id}")
        public Order subscribe(@DestinationVariable Long id) {
            return service.find(id);
        }
    }

    @Bean
    InMemoryRecorder recorder() {
        return new InMemoryRecorder();
    }
}
