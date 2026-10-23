package com.example.security;

import java.io.Serializable;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;

public class OrderPermissionEvaluator implements PermissionEvaluator {
    @Override
    public boolean hasPermission(Authentication auth, Object target, Object permission) {
        return false;
    }

    @Override
    public boolean hasPermission(Authentication auth, Serializable id, String type, Object permission) {
        return false;
    }
}
