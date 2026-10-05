package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.GateUser;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@SpringBootApplication
public class TestApp {

    /** The test gate is never reachable over TCP; pretend it is. */
    @Bean
    GateReachability testReachability() {
        return () -> true;
    }

    @RestController
    static class Api {

        @GetMapping("/api/hello")
        Map<String, Object> hello(@AuthenticationPrincipal GateUser user) {
            return Map.of("sub", user.subject(), "mode", user.mode().name(), "roles", user.roles());
        }

        @PostMapping("/api/echo")
        Map<String, Object> echo(@AuthenticationPrincipal GateUser user) {
            return Map.of("ok", true, "sub", user.subject());
        }

        @GetMapping("/page")
        String page() {
            return "page";
        }
    }
}
