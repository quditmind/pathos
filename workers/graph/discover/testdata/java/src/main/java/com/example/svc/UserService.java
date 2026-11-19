// Example service (test fixture for pathos-graph; not built).
package com.example.svc;

public class UserService {
    public String find(String id) {
        return normalise(lookup(id));
    }

    private String lookup(String id) {
        return "user-" + id;
    }

    public static String normalise(String s) {
        return s.trim();
    }
}
