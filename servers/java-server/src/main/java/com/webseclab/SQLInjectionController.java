package com.webseclab;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
@CrossOrigin(origins = "*")
public class SQLInjectionController {

    @Autowired
    private SQLInjectionService sqlInjectionService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // SQL Injection Test Endpoints
    @GetMapping(value = "/sql/vulnerable/login", produces = "application/json")
    public String sqlVulnerableLogin(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String password) {

        try {
            String payload = username != null ? username : (password != null ? password : "' OR '1'='1' --");
            String target = username != null ? "username" : "password";

            Map<String, String> parameters = new HashMap<>();
            parameters.put("test_type", "login");
            parameters.put("target", target);
            parameters.put("username", username != null ? username : "admin");
            parameters.put("password", password != null ? password : "password");

            Map<String, Object> result = sqlInjectionService.executeVulnerableCode(payload, parameters);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", result);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "vulnerable");
            metadata.put("timestamp", LocalDateTime.now().toString());
            response.put("metadata", metadata);

            return objectMapper.writeValueAsString(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "vulnerable");
            errorResponse.put("metadata", metadata);

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }

    @GetMapping(value = "/sql/safe/login", produces = "application/json")
    public String sqlSafeLogin(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String password) {

        try {
            String payload = username != null ? username : (password != null ? password : "admin");
            String target = username != null ? "username" : "password";

            Map<String, String> parameters = new HashMap<>();
            parameters.put("test_type", "login");
            parameters.put("target", target);
            parameters.put("username", username != null ? username : "admin");
            parameters.put("password", password != null ? password : "password");

            Map<String, Object> result = sqlInjectionService.executeSafeCode(payload, parameters);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", result);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "safe");
            metadata.put("timestamp", LocalDateTime.now().toString());
            response.put("metadata", metadata);

            return objectMapper.writeValueAsString(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "safe");
            errorResponse.put("metadata", metadata);

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }

    @GetMapping(value = "/sql/vulnerable/search", produces = "application/json")
    public String sqlVulnerableSearch(@RequestParam(defaultValue = "' UNION SELECT H2VERSION(), USER(), SCHEMA() --") String query) {
        try {
            Map<String, String> parameters = new HashMap<>();
            parameters.put("test_type", "search");

            Map<String, Object> result = sqlInjectionService.executeVulnerableCode(query, parameters);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", result);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "vulnerable");
            metadata.put("timestamp", LocalDateTime.now().toString());
            response.put("metadata", metadata);

            return objectMapper.writeValueAsString(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }

    @GetMapping(value = "/sql/safe/search", produces = "application/json")
    public String sqlSafeSearch(@RequestParam(defaultValue = "article") String query) {
        try {
            Map<String, String> parameters = new HashMap<>();
            parameters.put("test_type", "search");

            Map<String, Object> result = sqlInjectionService.executeSafeCode(query, parameters);

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", result);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", "safe");
            metadata.put("timestamp", LocalDateTime.now().toString());
            response.put("metadata", metadata);

            return objectMapper.writeValueAsString(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }
}