// Test fixture for the PATHOS graph rules (example code, not executed).
package com.example.web;

import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.annotation.KafkaListener;

// ruleid: pathos-graph-java-route-prefix-spring
@RequestMapping("/api/users")
@RestController
public class UserController {
    private final JdbcTemplate jdbc;
    private final KafkaTemplate<String, String> kafka;

    // ruleid: pathos-graph-java-route-spring
    @GetMapping("/{id}")
    public String get(@PathVariable String id) {
        // ruleid: pathos-graph-java-db-jdbc-read
        return jdbc.queryForObject("SELECT name FROM users WHERE id = ?", String.class, id);
    }

    // ruleid: pathos-graph-java-route-spring
    @PostMapping(value = "/", consumes = "application/json")
    public void create(@RequestBody String body) {
        // ruleid: pathos-graph-java-db-jdbc-write
        jdbc.update("INSERT INTO users(name) VALUES (?)", body);
        // ruleid: pathos-graph-java-queue-kafka-publish
        kafka.send("user-events", body);
        // ok: pathos-graph-java-db-jdbc-read, pathos-graph-java-db-jdbc-write
        jdbc.update(sql, body);
    }

    // ruleid: pathos-graph-java-queue-kafka-listener
    @KafkaListener(topics = "user-commands", groupId = "users")
    public void onCommand(String msg) {
        // ruleid: pathos-graph-java-http-call
        rest.getForObject("https://api.partner.example.net/users", String.class);
        // ok: pathos-graph-java-http-call
        log.info("https://docs.example.net/help");
    }
}
