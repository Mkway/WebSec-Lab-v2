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

    // 표준 엔드포인트 추가 (Dashboard 호환성)
    @PostMapping(value = "/vulnerabilities/sql-injection", produces = "application/json")
    public String sqlInjectionStandard(@RequestBody Map<String, Object> requestData) {
        try {
            String mode = (String) requestData.getOrDefault("mode", "vulnerable");
            String username = (String) requestData.getOrDefault("username", "admin");
            String password = (String) requestData.getOrDefault("password", "test");

            Map<String, String> parameters = new HashMap<>();
            parameters.put("test_type", "login");
            parameters.put("target", "username");
            parameters.put("username", username);
            parameters.put("password", password);

            Map<String, Object> result;
            if ("vulnerable".equals(mode)) {
                result = sqlInjectionService.executeVulnerableCode(username, parameters);
            } else {
                result = sqlInjectionService.executeSafeCode(username, parameters);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success", true);
            response.put("data", result);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "sql_injection");
            metadata.put("mode", mode);
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
            metadata.put("mode", requestData.getOrDefault("mode", "vulnerable"));
            errorResponse.put("metadata", metadata);

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }

    // XSS Test Endpoint
    @PostMapping(value = "/vulnerabilities/xss", produces = "application/json")
    public String xssTest(@RequestBody Map<String, Object> requestData) {
        try {
            String mode = (String) requestData.getOrDefault("mode", "vulnerable");
            String payload = (String) requestData.getOrDefault("payload", "<script>alert(\"XSS\")</script>");

            Map<String, Object> response = new HashMap<>();
            Map<String, Object> data = new HashMap<>();

            if ("vulnerable".equals(mode)) {
                // 취약한 코드 - 직접 출력
                String result = "<h1>User Input: " + payload + "</h1>";
                boolean attackSuccess = payload.contains("<script>") || payload.contains("javascript:");

                data.put("result", result);
                data.put("vulnerability_detected", attackSuccess);
                data.put("payload_used", payload);
                data.put("attack_success", attackSuccess);
                data.put("execution_time", "0.001s");
            } else {
                // 안전한 코드 - HTML 이스케이프
                String safeInput = payload.replace("<", "&lt;").replace(">", "&gt;");
                String result = "<h1>User Input: " + safeInput + "</h1>";

                data.put("result", result);
                data.put("vulnerability_detected", false);
                data.put("payload_used", payload);
                data.put("attack_success", false);
                data.put("execution_time", "0.001s");
            }

            response.put("success", true);
            response.put("data", data);

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "xss");
            metadata.put("mode", mode);
            metadata.put("timestamp", LocalDateTime.now().toString());
            response.put("metadata", metadata);

            return objectMapper.writeValueAsString(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("success", false);
            errorResponse.put("error", e.getMessage());

            Map<String, Object> metadata = new HashMap<>();
            metadata.put("language", "java");
            metadata.put("vulnerability_type", "xss");
            metadata.put("mode", requestData.getOrDefault("mode", "vulnerable"));
            errorResponse.put("metadata", metadata);

            try {
                return objectMapper.writeValueAsString(errorResponse);
            } catch (Exception jsonEx) {
                return "{\"success\": false, \"error\": \"JSON serialization failed\"}";
            }
        }
    }
}