package com.example.demo;

import java.util.Arrays;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.cors.CorsConfiguration;

@Configuration
// ruleid: pathos.misconfig.spring.web-security-debug
@EnableWebSecurity(debug = true)
public class SecurityConfig {

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        // ruleid: pathos.misconfig.spring.csrf-disabled
        http.csrf().disable();
        // ruleid: pathos.misconfig.spring.permitall-sensitive-path
        http.authorizeRequests().antMatchers("/actuator/**").permitAll();
        // ok: pathos.misconfig.spring.permitall-sensitive-path
        http.authorizeRequests().antMatchers("/public/**").permitAll();
        // ruleid: pathos.misconfig.spring.permitall-any-request
        http.authorizeRequests().anyRequest().permitAll();
        return http.build();
    }

    @Bean
    SecurityFilterChain modern(HttpSecurity http) throws Exception {
        // ruleid: pathos.misconfig.spring.csrf-disabled
        http.csrf(AbstractHttpConfigurer::disable);
        // ruleid: pathos.misconfig.spring.permitall-sensitive-path
        http.authorizeHttpRequests(auth -> auth.requestMatchers("/h2-console/**").permitAll());
        // ok: pathos.misconfig.spring.permitall-any-request
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        return http.build();
    }

    @Bean
    SecurityFilterChain lambda(HttpSecurity http) throws Exception {
        // ruleid: pathos.misconfig.spring.csrf-disabled
        http.csrf(csrf -> csrf.disable());
        // ok: pathos.misconfig.spring.csrf-disabled
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/webhook"));
        return http.build();
    }

    CorsConfiguration cors() {
        CorsConfiguration c = new CorsConfiguration();
        // ruleid: pathos.misconfig.spring.cors-wildcard-origin
        c.addAllowedOrigin("*");
        // ruleid: pathos.misconfig.spring.cors-wildcard-origin
        c.setAllowedOrigins(List.of("*"));
        // ok: pathos.misconfig.spring.cors-wildcard-origin
        c.setAllowedOrigins(Arrays.asList("https://app.example.com"));
        return c;
    }
}

// ruleid: pathos.misconfig.spring.cors-wildcard-origin
@CrossOrigin(origins = "*")
class OpenController {
}

// ok: pathos.misconfig.spring.cors-wildcard-origin
@CrossOrigin(origins = "https://app.example.com")
class TrustedController {
}
