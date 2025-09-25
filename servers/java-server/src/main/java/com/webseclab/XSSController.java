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


}