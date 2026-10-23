package com.example.security;

import org.springframework.stereotype.Component;

@Component("guard")
public class AccessGuard {
    public boolean canReadOrder(Long orderId) {
        return true;
    }

    public void checkTenant(String tenantId) {
    }

    public String describe() {
        return "not a check";
    }
}
