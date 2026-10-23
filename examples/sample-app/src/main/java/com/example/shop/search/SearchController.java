package com.example.shop.search;

import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SearchController {
    private final JdbcTemplate jdbc;

    SearchController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/api/v1/products/search")
    @PreAuthorize("hasAuthority('SCOPE_products:read')")
    public List<Map<String, Object>> search(@RequestParam String q) {
        return jdbc.queryForList("SELECT id, name, price FROM product WHERE name LIKE '%" + q + "%'");
    }
}
