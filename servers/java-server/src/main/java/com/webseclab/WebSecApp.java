package com.webseclab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.CrossOrigin;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
@RestController
@CrossOrigin(origins = "*")
public class WebSecApp {

    @GetMapping("/health")
    public Map<String, Object> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "websec-java");
        response.put("timestamp", LocalDateTime.now().toString());
        return response;
    }

    @GetMapping("/")
    public Map<String, Object> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "WebSec-Lab Java Server");
        response.put("version", "2.0.0");
        response.put("endpoints", new String[]{"/health", "/vulnerabilities"});
        return response;
    }

    @GetMapping("/vulnerabilities")
    public Map<String, Object> vulnerabilities() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "WebSec-Lab Java Server");
        response.put("available", new String[]{
            "GET /health"
        });
        return response;
    }

    public static void main(String[] args) {
        SpringApplication.run(WebSecApp.class, args);
    }
}