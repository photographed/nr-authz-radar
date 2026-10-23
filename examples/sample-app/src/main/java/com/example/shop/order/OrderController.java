package com.example.shop.order;

import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/orders")
public class OrderController {
    private final OrderRepository orders;

    OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_orders:read')")
    public Order get(@PathVariable Long id) {
        return orders.findById(id).orElseThrow();                 // no owner check
    }

    @GetMapping("/{id}/receipt")
    @PreAuthorize("hasAuthority('SCOPE_orders:read')")
    public Order receipt(@PathVariable Long id, Principal me) {
        return orders.findByIdAndOwnerId(id, me.getName()).orElseThrow();   // OK
    }

    @PostMapping("/{id}/cancel")
    @PreAuthorize("hasAuthority('SCOPE_orders:read')")         // write operation behind a read scope
    public void cancel(@PathVariable Long id, Principal me) {
        Order o = orders.findByIdAndOwnerId(id, me.getName()).orElseThrow();
        o.status = "CANCELLED";
        orders.save(o);
    }
}
