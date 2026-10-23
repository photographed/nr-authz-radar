package com.example.shop.order;

import org.springframework.graphql.data.method.annotation.Argument;
import org.springframework.graphql.data.method.annotation.QueryMapping;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;

@Controller
public class OrderGraphQl {
    private final OrderRepository orders;

    OrderGraphQl(OrderRepository orders) {
        this.orders = orders;
    }

    @QueryMapping
    @PreAuthorize("hasAuthority('SCOPE_orders:read')")
    public Order order(@Argument Long id) {
        return orders.findById(id).orElse(null);                  // no owner check
    }
}
