package com.example.order;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OrderController {
    @GetMapping("/orders/{id}")
    @PreAuthorize("hasAuthority('SCOPE_orders:read') and @guard.canReadOrder(#id)")
    public String get(Long id) {
        return "";
    }

    public void checkSomething() {
    }
}
