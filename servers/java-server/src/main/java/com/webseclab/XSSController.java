package com.webseclab;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

@RestController
@CrossOrigin(origins = "*")
public class XSSController {

    // XSS Test Endpoints
    @GetMapping(value = "/xss/vulnerable", produces = "text/html")
    public String xssVulnerable(@RequestParam(defaultValue = "<script>alert('XSS')</script>") String input) {
        // 취약한 코드 - 직접 출력
        return "<h1>User Input: " + input + "</h1>";
    }

    @GetMapping(value = "/xss/safe", produces = "text/html")
    public String xssSafe(@RequestParam(defaultValue = "<script>alert('XSS')</script>") String input) {
        // 안전한 코드 - HTML 이스케이프
        String safeInput = HtmlUtils.htmlEscape(input);
        return "<h1>User Input: " + safeInput + "</h1>";
    }

    @GetMapping("/vulnerabilities")
    public String vulnerabilities() {
        return "{\"message\": \"WebSec-Lab Java Server\", \"available\": [\"GET /xss/vulnerable\", \"GET /xss/safe\", \"GET /sql/vulnerable/login\", \"GET /sql/safe/login\", \"GET /sql/vulnerable/search\", \"GET /sql/safe/search\"]}";
    }

    @GetMapping("/health")
    public String health() {
        return "{\"status\": \"healthy\", \"service\": \"websec-java\"}";
    }

    @GetMapping("/")
    public String home() {
        return "{\"message\": \"WebSec-Lab Java Server\", \"version\": \"2.0.0\", \"endpoints\": [\"/health\", \"/xss/vulnerable\", \"/xss/safe\"]}";
    }
}