package com.webseclab;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@OpenAPIDefinition(
    info = @Info(
        title = "WebSec-Lab Java API",
        version = "2.0.0",
        description = "Java Web Security Testing Platform"
    )
)
@Tag(name = "WebSec Lab", description = "Java vulnerability testing endpoints")
public class WebSecApp {

    @GetMapping("/health")
    @Operation(summary = "Health Check", description = "Check if the server is running and healthy")
    public Map<String, Object> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "websec-java");
        response.put("timestamp", LocalDateTime.now().toString());
        return response;
    }

    @GetMapping("/")
    @Operation(summary = "Server Information", description = "Get basic server information and available endpoints")
    public Map<String, Object> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "WebSec-Lab Java Server");
        response.put("version", "2.0.0");
        response.put("endpoints", new String[]{"/health", "/vulnerabilities", "/swagger-ui/index.html", "/v3/api-docs"});
        return response;
    }

    @GetMapping("/vulnerabilities")
    @Operation(summary = "List Available Vulnerabilities", description = "Get a list of all supported vulnerability types")
    public Map<String, Object> vulnerabilities() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "WebSec-Lab Java Server");
        response.put("available", new String[]{
            "GET /health",
            "GET /swagger-ui/index.html",
            "GET /v3/api-docs"
        });
        return response;
    }

    public static void main(String[] args) {
        SpringApplication.run(WebSecApp.class, args);
    }
}