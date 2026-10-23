package com.example.shop.admin;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {
    public record RoleChange(String role) { }

    @PutMapping("/api/admin/users/{id}/role")
    public void changeRole(@PathVariable Long id, @RequestBody RoleChange change) {
        // any authenticated user can reach this
    }
}
