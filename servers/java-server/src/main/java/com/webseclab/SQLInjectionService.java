package com.webseclab;

import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;
import java.sql.*;
import java.util.*;

/**
 * H2 Database SQL Injection Vulnerability Module
 * PayloadsAllTheThings 기반의 실제 SQL 인젝션 테스트
 */
@Service
public class SQLInjectionService {

    private static final String DB_URL = "jdbc:h2:mem:websec_test;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    @PostConstruct
    public void initializeDatabase() {
        try {
            Class.forName("org.h2.Driver");
            initializeTestData();
        } catch (ClassNotFoundException e) {
            System.err.println("H2 Driver not found: " + e.getMessage());
        }
    }

    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    /**
     * 취약한 코드 실행 (실제 SQL 인젝션 허용)
     */
    public Map<String, Object> executeVulnerableCode(String payload, Map<String, String> parameters) {
        String testType = parameters.getOrDefault("test_type", "login");
        String target = parameters.getOrDefault("target", "username");

        try {
            switch (testType) {
                case "login":
                    return vulnerableLogin(payload, target, parameters);
                case "search":
                    return vulnerableSearch(payload);
                case "union":
                    return vulnerableUnionSelect(payload);
                case "blind":
                    return vulnerableBlindInjection(payload);
                case "time":
                    return vulnerableTimeBasedInjection(payload);
                default:
                    return vulnerableLogin(payload, target, parameters);
            }
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("payload_executed", true);
            result.put("sql_error", true);
            result.put("educational_note", "SQL error occurred - indicates potential injection vulnerability");
            return result;
        }
    }

    /**
     * 안전한 코드 실행 (SQL 인젝션 방지)
     */
    public Map<String, Object> executeSafeCode(String payload, Map<String, String> parameters) {
        String testType = parameters.getOrDefault("test_type", "login");
        String target = parameters.getOrDefault("target", "username");

        try {
            switch (testType) {
                case "login":
                    return safeLogin(payload, target, parameters);
                case "search":
                    return safeSearch(payload);
                case "union":
                    return safeUnionSelect(payload);
                case "blind":
                    return safeBlindInjection(payload);
                case "time":
                    return safeTimeBasedInjection(payload);
                default:
                    return safeLogin(payload, target, parameters);
            }
        } catch (Exception e) {
            Map<String, Object> result = new HashMap<>();
            result.put("success", false);
            result.put("error", "Safe code execution failed");
            result.put("payload_executed", false);
            result.put("educational_note", "Parameterized queries prevent SQL injection");
            return result;
        }
    }

    /**
     * 취약한 로그인 함수 (인젝션 허용)
     */
    private Map<String, Object> vulnerableLogin(String payload, String target, Map<String, String> parameters) throws SQLException {
        // PayloadsAllTheThings 기반 H2 페이로드들
        List<String> testPayloads = Arrays.asList(
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "' OR 1=1--",
            "' UNION SELECT H2VERSION(), USER(), SCHEMA() --",
            "'; SELECT CURRENT_TIMESTAMP() --"
        );

        String username, password;
        if ("username".equals(target)) {
            username = payload;
            password = parameters.getOrDefault("password", "password");
        } else {
            username = parameters.getOrDefault("username", "admin");
            password = payload;
        }

        // 취약한 쿼리 (직접 문자열 삽입)
        String sql = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND password = '" + password + "'";

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> users = new ArrayList<>();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", rs.getInt("id"));
                user.put("username", rs.getString("username"));
                user.put("role", rs.getString("role"));
                users.add(user);
            }

            result.put("success", true);
            result.put("vulnerable_query", sql);
            result.put("payload_injected", payload);
            result.put("results_count", users.size());
            result.put("data", users);
            result.put("authentication_bypassed", users.size() > 0);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("vulnerability_type", "SQL Injection - Authentication Bypass");
            educationalAnalysis.put("attack_vector", "Direct string concatenation in SQL query");
            educationalAnalysis.put("impact", "Unauthorized access to user accounts");
            educationalAnalysis.put("example_payloads", testPayloads);
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", users.size() > 0 ? "HIGH - Authentication bypassed!" : "Injection attempted but no data returned");

        } catch (SQLException e) {
            result.put("success", false);
            result.put("vulnerable_query", sql);
            result.put("sql_error", e.getMessage());
            result.put("payload_injected", payload);
            result.put("educational_note", "H2 SQL syntax error - indicates successful injection of malformed SQL");
            result.put("security_impact", "CRITICAL - SQL injection vulnerability confirmed");
        }

        return result;
    }

    /**
     * 안전한 로그인 함수 (파라미터화된 쿼리)
     */
    private Map<String, Object> safeLogin(String payload, String target, Map<String, String> parameters) throws SQLException {
        String username, password;
        if ("username".equals(target)) {
            username = payload;
            password = parameters.getOrDefault("password", "password");
        } else {
            username = parameters.getOrDefault("username", "admin");
            password = payload;
        }

        // 안전한 쿼리 (파라미터화된 쿼리)
        String sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> users = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            pstmt.setString(2, password);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getInt("id"));
                    user.put("username", rs.getString("username"));
                    user.put("role", rs.getString("role"));
                    users.add(user);
                }
            }

            result.put("success", true);
            result.put("safe_query", sql);
            result.put("parameters", Arrays.asList(username, password));
            result.put("results_count", users.size());
            result.put("data", users);
            result.put("authentication_bypassed", false);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("protection_method", "Parameterized Query (Prepared Statement)");
            educationalAnalysis.put("why_safe", "User input is treated as data, not SQL code");
            educationalAnalysis.put("security_benefit", "SQL injection is impossible with proper parameterization");
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", "NONE - Properly protected against SQL injection");

        } catch (SQLException e) {
            result.put("success", false);
            result.put("safe_query", sql);
            result.put("error", "Database error (not SQL injection)");
            result.put("educational_note", "Legitimate database errors can still occur with safe queries");
        }

        return result;
    }

    /**
     * 취약한 검색 함수 (UNION 인젝션 허용)
     */
    private Map<String, Object> vulnerableSearch(String payload) throws SQLException {
        List<String> unionPayloads = Arrays.asList(
            "' UNION SELECT H2VERSION(), USER(), SCHEMA() --",
            "' UNION SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS --",
            "' UNION SELECT username, password, role FROM users --",
            "'; SELECT CURRENT_TIMESTAMP() --"
        );

        String sql = "SELECT id, title, content FROM articles WHERE title LIKE '%" + payload + "%'";

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> articles = new ArrayList<>();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, Object> article = new HashMap<>();
                article.put("id", rs.getInt("id"));
                article.put("title", rs.getString("title"));
                article.put("content", rs.getString("content"));
                articles.add(article);
            }

            result.put("success", true);
            result.put("vulnerable_query", sql);
            result.put("payload_injected", payload);
            result.put("results_count", articles.size());
            result.put("data", articles);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("vulnerability_type", "SQL Injection - UNION Attack");
            educationalAnalysis.put("attack_vector", "UNION SELECT to extract additional data");
            educationalAnalysis.put("potential_data_exposure", "Database schema, user credentials, sensitive data");
            educationalAnalysis.put("example_payloads", unionPayloads);
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", articles.size() > 3 ? "HIGH - Potential data extraction via UNION" : "Search executed with injection point");

        } catch (SQLException e) {
            result.put("success", false);
            result.put("vulnerable_query", sql);
            result.put("sql_error", e.getMessage());
            result.put("payload_injected", payload);
            result.put("educational_note", "UNION injection syntax error - vulnerability confirmed");
        }

        return result;
    }

    /**
     * 안전한 검색 함수
     */
    private Map<String, Object> safeSearch(String payload) throws SQLException {
        String sql = "SELECT id, title, content FROM articles WHERE title LIKE ?";

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> articles = new ArrayList<>();

        try (Connection conn = getConnection();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, "%" + payload + "%");

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> article = new HashMap<>();
                    article.put("id", rs.getInt("id"));
                    article.put("title", rs.getString("title"));
                    article.put("content", rs.getString("content"));
                    articles.add(article);
                }
            }

            result.put("success", true);
            result.put("safe_query", sql);
            result.put("search_term", payload);
            result.put("results_count", articles.size());
            result.put("data", articles);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("protection_method", "Parameterized Search Query");
            educationalAnalysis.put("why_safe", "Search term treated as literal string, not SQL code");
            educationalAnalysis.put("additional_protection", "Input validation can provide extra security layer");
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", "NONE - Protected against UNION injection attacks");

        } catch (SQLException e) {
            result.put("success", false);
            result.put("safe_query", sql);
            result.put("error", "Database error (not SQL injection)");
        }

        return result;
    }

    /**
     * Blind SQL Injection (취약한 버전)
     */
    private Map<String, Object> vulnerableBlindInjection(String payload) throws SQLException {
        String sql = "SELECT COUNT(*) FROM users WHERE id = " + payload;

        Map<String, Object> result = new HashMap<>();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            int count = 0;
            if (rs.next()) {
                count = rs.getInt(1);
            }

            result.put("success", true);
            result.put("vulnerable_query", sql);
            result.put("payload_injected", payload);
            result.put("result", count);
            result.put("boolean_result", count > 0);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("vulnerability_type", "Blind SQL Injection - Boolean Based");
            educationalAnalysis.put("attack_method", "True/False responses reveal information");
            educationalAnalysis.put("example_payloads", Arrays.asList(
                "1 AND 1=1",
                "1 AND 1=2",
                "1 AND (SELECT COUNT(*) FROM users) > 0",
                "1 AND SUBSTRING((SELECT username FROM users LIMIT 1), 1, 1) = 'a'"
            ));
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", "MEDIUM - Data can be extracted character by character");

        } catch (SQLException e) {
            result.put("success", false);
            result.put("vulnerable_query", sql);
            result.put("sql_error", e.getMessage());
            result.put("educational_note", "Blind injection syntax error reveals vulnerability");
        }

        return result;
    }

    /**
     * 안전한 Blind 쿼리
     */
    private Map<String, Object> safeBlindInjection(String payload) throws SQLException {
        Map<String, Object> result = new HashMap<>();

        try {
            // 입력값 검증
            int numericPayload = Integer.parseInt(payload);

            String sql = "SELECT COUNT(*) FROM users WHERE id = ?";

            try (Connection conn = getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setInt(1, numericPayload);

                try (ResultSet rs = pstmt.executeQuery()) {
                    int count = 0;
                    if (rs.next()) {
                        count = rs.getInt(1);
                    }

                    result.put("success", true);
                    result.put("safe_query", sql);
                    result.put("validated_input", payload);
                    result.put("result", count);
                    result.put("boolean_result", count > 0);

                    Map<String, Object> educationalAnalysis = new HashMap<>();
                    educationalAnalysis.put("protection_method", "Input Validation + Parameterized Query");
                    educationalAnalysis.put("validation_applied", "Numeric input validation");
                    educationalAnalysis.put("why_safe", "Invalid input rejected before reaching database");
                    educationalAnalysis.put("database_type", "H2 Database");
                    result.put("educational_analysis", educationalAnalysis);

                    result.put("security_impact", "NONE - Protected against blind injection");
                }
            }

        } catch (NumberFormatException e) {
            result.put("success", false);
            result.put("error", "Invalid input - numeric value required");
            result.put("educational_note", "Input validation prevents injection attempts");
        } catch (SQLException e) {
            result.put("success", false);
            result.put("safe_query", "SELECT COUNT(*) FROM users WHERE id = ?");
            result.put("error", "Database error (not SQL injection)");
        }

        return result;
    }

    /**
     * Time-based Blind SQL Injection (취약한 버전)
     */
    private Map<String, Object> vulnerableTimeBasedInjection(String payload) throws SQLException {
        long startTime = System.currentTimeMillis();
        String sql = "SELECT * FROM users WHERE id = " + payload;

        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> data = new ArrayList<>();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", rs.getInt("id"));
                user.put("username", rs.getString("username"));
                user.put("role", rs.getString("role"));
                data.add(user);
            }

            long executionTime = System.currentTimeMillis() - startTime;

            result.put("success", true);
            result.put("vulnerable_query", sql);
            result.put("payload_injected", payload);
            result.put("execution_time", executionTime / 1000.0);
            result.put("data", data);

            Map<String, Object> educationalAnalysis = new HashMap<>();
            educationalAnalysis.put("vulnerability_type", "Time-based Blind SQL Injection");
            educationalAnalysis.put("attack_method", "Database delays reveal information");
            educationalAnalysis.put("example_payloads", Arrays.asList(
                "1; SELECT SLEEP(5) FROM DUAL",  // MySQL style (for reference)
                "1 AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%USER%') > 0",
                "1; CALL SYSTEM_IN('ping -c 5 127.0.0.1')",  // H2 specific
                "1 AND (CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES) ELSE 0 END) > 0"
            ));
            educationalAnalysis.put("database_type", "H2 Database");
            result.put("educational_analysis", educationalAnalysis);

            result.put("security_impact", executionTime > 1000 ? "HIGH - Time delay indicates injection success" : "Injection attempted");

        } catch (SQLException e) {
            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", false);
            result.put("vulnerable_query", sql);
            result.put("sql_error", e.getMessage());
            result.put("execution_time", executionTime / 1000.0);
            result.put("educational_note", "Time-based injection syntax error");
        }

        return result;
    }

    /**
     * 안전한 Time-based 쿼리
     */
    private Map<String, Object> safeTimeBasedInjection(String payload) throws SQLException {
        long startTime = System.currentTimeMillis();
        Map<String, Object> result = new HashMap<>();

        try {
            int numericPayload = Integer.parseInt(payload);
            String sql = "SELECT * FROM users WHERE id = ?";

            List<Map<String, Object>> data = new ArrayList<>();

            try (Connection conn = getConnection();
                 PreparedStatement pstmt = conn.prepareStatement(sql)) {

                pstmt.setInt(1, numericPayload);

                try (ResultSet rs = pstmt.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> user = new HashMap<>();
                        user.put("id", rs.getInt("id"));
                        user.put("username", rs.getString("username"));
                        user.put("role", rs.getString("role"));
                        data.add(user);
                    }
                }

                long executionTime = System.currentTimeMillis() - startTime;

                result.put("success", true);
                result.put("safe_query", sql);
                result.put("validated_input", payload);
                result.put("execution_time", executionTime / 1000.0);
                result.put("data", data);

                Map<String, Object> educationalAnalysis = new HashMap<>();
                educationalAnalysis.put("protection_method", "Parameterized Query with Input Validation");
                educationalAnalysis.put("timing_protection", "Consistent execution time regardless of input");
                educationalAnalysis.put("why_safe", "No SQL code injection possible");
                educationalAnalysis.put("database_type", "H2 Database");
                result.put("educational_analysis", educationalAnalysis);

                result.put("security_impact", "NONE - Protected against time-based injection");
            }

        } catch (NumberFormatException e) {
            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", false);
            result.put("error", "Invalid input - numeric value required");
            result.put("execution_time", executionTime / 1000.0);
            result.put("educational_note", "Input validation prevents time-based attacks");
        } catch (SQLException e) {
            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", false);
            result.put("safe_query", "SELECT * FROM users WHERE id = ?");
            result.put("error", "Database error (not SQL injection)");
            result.put("execution_time", executionTime / 1000.0);
        }

        return result;
    }

    /**
     * 취약한 UNION SELECT 실행
     */
    private Map<String, Object> vulnerableUnionSelect(String payload) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        long startTime = System.currentTimeMillis();

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            String query = "SELECT id, username FROM users WHERE id = " + payload;
            result.put("vulnerable_query", query);
            result.put("payload_used", payload);

            ResultSet rs = stmt.executeQuery(query);
            List<Map<String, Object>> data = new ArrayList<>();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                data.add(row);
            }

            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", true);
            result.put("data", data);
            result.put("attack_successful", true);
            result.put("execution_time", executionTime / 1000.0);
            result.put("educational_note", "UNION SELECT attack successful - database structure exposed");

        } catch (SQLException e) {
            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("sql_error", true);
            result.put("execution_time", executionTime / 1000.0);
        }

        return result;
    }

    /**
     * 안전한 UNION SELECT 실행 (방어)
     */
    private Map<String, Object> safeUnionSelect(String payload) throws SQLException {
        Map<String, Object> result = new HashMap<>();
        long startTime = System.currentTimeMillis();

        try (Connection conn = getConnection()) {
            // Prepared statement 사용으로 SQL 인젝션 방지
            String query = "SELECT id, username FROM users WHERE id = ?";
            PreparedStatement pstmt = conn.prepareStatement(query);

            try {
                int id = Integer.parseInt(payload);
                pstmt.setInt(1, id);
            } catch (NumberFormatException e) {
                result.put("success", false);
                result.put("error", "Invalid input: ID must be a number");
                result.put("safe_query", query);
                result.put("educational_note", "Input validation prevents injection");
                return result;
            }

            result.put("safe_query", query);
            result.put("payload_sanitized", payload);

            ResultSet rs = pstmt.executeQuery();
            List<Map<String, Object>> data = new ArrayList<>();

            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                data.add(row);
            }

            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", true);
            result.put("data", data);
            result.put("attack_prevented", true);
            result.put("execution_time", executionTime / 1000.0);
            result.put("educational_note", "Prepared statement prevents UNION SELECT injection");

        } catch (SQLException e) {
            long executionTime = System.currentTimeMillis() - startTime;
            result.put("success", false);
            result.put("error", "Database error (not SQL injection)");
            result.put("execution_time", executionTime / 1000.0);
        }

        return result;
    }

    /**
     * 테스트 데이터 초기화
     */
    private void initializeTestData() {
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            // 사용자 테이블 생성
            stmt.execute("DROP TABLE IF EXISTS users");
            stmt.execute("""
                CREATE TABLE users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user'
                )
            """);

            // 게시글 테이블 생성
            stmt.execute("DROP TABLE IF EXISTS articles");
            stmt.execute("""
                CREATE TABLE articles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    content TEXT
                )
            """);

            // 테스트 데이터 삽입
            stmt.execute("""
                INSERT INTO users (username, password, role) VALUES
                ('admin', 'admin123', 'admin'),
                ('user1', 'password1', 'user'),
                ('user2', 'password2', 'user'),
                ('test', 'test123', 'user')
            """);

            stmt.execute("""
                INSERT INTO articles (title, content) VALUES
                ('First Article', 'This is the first article content'),
                ('Second Article', 'This is the second article content'),
                ('Security Guide', 'How to prevent SQL injection attacks')
            """);

        } catch (SQLException e) {
            System.err.println("Failed to initialize SQL injection test data: " + e.getMessage());
        }
    }
}