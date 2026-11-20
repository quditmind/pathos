// Example Spring controller (test fixture for pathos-graph; not built).
package com.example.web;

import com.example.svc.UserService;

public class UserController {
    private final UserService users;

    public UserController(UserService users) {
        this.users = users;
    }

    public String get(String id) {
        String u = users.find(id);
        return format(u);
    }

    private String format(String u) {
        return UserService.normalise(u);
    }
}
