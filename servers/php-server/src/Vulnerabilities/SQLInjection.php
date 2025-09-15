<?php

namespace WebSecLab\Vulnerabilities;

use WebSecLab\Utils\DatabaseManager;

/**
 * SQL Injection Vulnerability Module
 * PayloadsAllTheThings 기반의 실제 SQL 인젝션 테스트
 */
class SQLInjection implements VulnerabilityInterface
{
    private DatabaseManager $db;

    public function __construct()
    {
        $this->db = DatabaseManager::getInstance();
        $this->initializeTestData();
    }

    /**
     * 취약한 코드 실행 (실제 SQL 인젝션 허용)
     */
    public function executeVulnerableCode(string $payload, array $parameters = []): array
    {
        $testType = $parameters['test_type'] ?? 'login';
        $target = $parameters['target'] ?? 'username';

        try {
            switch ($testType) {
                case 'login':
                    return $this->vulnerableLogin($payload, $target);
                case 'search':
                    return $this->vulnerableSearch($payload);
                case 'union':
                    return $this->vulnerableUnionSelect($payload);
                case 'blind':
                    return $this->vulnerableBlindInjection($payload);
                case 'time':
                    return $this->vulnerableTimeBasedInjection($payload);
                default:
                    return $this->vulnerableLogin($payload, $target);
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'payload_executed' => true,
                'sql_error' => true,
                'educational_note' => 'SQL error occurred - this indicates potential injection vulnerability'
            ];
        }
    }

    /**
     * 안전한 코드 실행 (SQL 인젝션 방지)
     */
    public function executeSafeCode(string $payload, array $parameters = []): array
    {
        $testType = $parameters['test_type'] ?? 'login';
        $target = $parameters['target'] ?? 'username';

        try {
            switch ($testType) {
                case 'login':
                    return $this->safeLogin($payload, $target);
                case 'search':
                    return $this->safeSearch($payload);
                case 'union':
                    return $this->safeUnionSelect($payload);
                case 'blind':
                    return $this->safeBlindInjection($payload);
                case 'time':
                    return $this->safeTimeBasedInjection($payload);
                default:
                    return $this->safeLogin($payload, $target);
            }
        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => 'Safe code execution failed',
                'payload_executed' => false,
                'educational_note' => 'Parameterized queries prevent SQL injection'
            ];
        }
    }

    /**
     * 취약한 로그인 함수 (인젝션 허용)
     */
    private function vulnerableLogin(string $payload, string $target): array
    {
        // PayloadsAllTheThings 기반 페이로드들
        $testPayloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin' #",
            "admin'/*",
            "' OR 1=1--",
            "' OR 1=1#",
            "' UNION SELECT 1,user(),version()--"
        ];

        if ($target === 'username') {
            $username = $payload;
            $password = $parameters['password'] ?? 'password';
        } else {
            $username = $parameters['username'] ?? 'admin';
            $password = $payload;
        }

        // 취약한 쿼리 (직접 문자열 삽입)
        $sql = "SELECT id, username, role FROM users WHERE username = '$username' AND password = '$password'";
        
        try {
            $pdo = $this->db->getConnection();
            $result = $pdo->query($sql);
            $users = $result ? $result->fetchAll(\PDO::FETCH_ASSOC) : [];

            return [
                'success' => true,
                'vulnerable_query' => $sql,
                'payload_injected' => $payload,
                'results_count' => count($users),
                'data' => $users,
                'authentication_bypassed' => count($users) > 0,
                'educational_analysis' => [
                    'vulnerability_type' => 'SQL Injection - Authentication Bypass',
                    'attack_vector' => 'Direct string concatenation in SQL query',
                    'impact' => 'Unauthorized access to user accounts',
                    'example_payloads' => $testPayloads
                ],
                'security_impact' => count($users) > 0 ? 'HIGH - Authentication bypassed!' : 'Injection attempted but no data returned'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'vulnerable_query' => $sql,
                'sql_error' => $e->getMessage(),
                'payload_injected' => $payload,
                'educational_note' => 'SQL syntax error - indicates successful injection of malformed SQL',
                'security_impact' => 'CRITICAL - SQL injection vulnerability confirmed'
            ];
        }
    }

    /**
     * 안전한 로그인 함수 (파라미터화된 쿼리)
     */
    private function safeLogin(string $payload, string $target): array
    {
        if ($target === 'username') {
            $username = $payload;
            $password = $parameters['password'] ?? 'password';
        } else {
            $username = $parameters['username'] ?? 'admin';
            $password = $payload;
        }

        // 안전한 쿼리 (파라미터화된 쿼리)
        $sql = "SELECT id, username, role FROM users WHERE username = ? AND password = ?";
        
        try {
            $pdo = $this->db->getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$username, $password]);
            $users = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            return [
                'success' => true,
                'safe_query' => $sql,
                'parameters' => [$username, $password],
                'results_count' => count($users),
                'data' => $users,
                'authentication_bypassed' => false,
                'educational_analysis' => [
                    'protection_method' => 'Parameterized Query (Prepared Statement)',
                    'why_safe' => 'User input is treated as data, not SQL code',
                    'security_benefit' => 'SQL injection is impossible with proper parameterization'
                ],
                'security_impact' => 'NONE - Properly protected against SQL injection'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'safe_query' => $sql,
                'error' => 'Database error (not SQL injection)',
                'educational_note' => 'Legitimate database errors can still occur with safe queries'
            ];
        }
    }

    /**
     * 취약한 검색 함수 (UNION 인젝션 허용)
     */
    private function vulnerableSearch(string $payload): array
    {
        // UNION 기반 페이로드들
        $unionPayloads = [
            "' UNION SELECT 1,user(),version()--",
            "' UNION SELECT 1,database(),@@version--",
            "' UNION SELECT 1,table_name,column_name FROM information_schema.columns--",
            "' UNION SELECT 1,username,password FROM users--"
        ];

        $sql = "SELECT id, title, content FROM articles WHERE title LIKE '%$payload%'";
        
        try {
            $pdo = $this->db->getConnection();
            $result = $pdo->query($sql);
            $articles = $result ? $result->fetchAll(\PDO::FETCH_ASSOC) : [];

            return [
                'success' => true,
                'vulnerable_query' => $sql,
                'payload_injected' => $payload,
                'results_count' => count($articles),
                'data' => $articles,
                'educational_analysis' => [
                    'vulnerability_type' => 'SQL Injection - UNION Attack',
                    'attack_vector' => 'UNION SELECT to extract additional data',
                    'potential_data_exposure' => 'Database schema, user credentials, sensitive data',
                    'example_payloads' => $unionPayloads
                ],
                'security_impact' => count($articles) > 3 ? 'HIGH - Potential data extraction via UNION' : 'Search executed with injection point'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'vulnerable_query' => $sql,
                'sql_error' => $e->getMessage(),
                'payload_injected' => $payload,
                'educational_note' => 'UNION injection syntax error - vulnerability confirmed'
            ];
        }
    }

    /**
     * 안전한 검색 함수
     */
    private function safeSearch(string $payload): array
    {
        $sql = "SELECT id, title, content FROM articles WHERE title LIKE ?";
        
        try {
            $pdo = $this->db->getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute(["%$payload%"]);
            $articles = $stmt->fetchAll(\PDO::FETCH_ASSOC);

            return [
                'success' => true,
                'safe_query' => $sql,
                'search_term' => $payload,
                'results_count' => count($articles),
                'data' => $articles,
                'educational_analysis' => [
                    'protection_method' => 'Parameterized Search Query',
                    'why_safe' => 'Search term treated as literal string, not SQL code',
                    'additional_protection' => 'Input validation can provide extra security layer'
                ],
                'security_impact' => 'NONE - Protected against UNION injection attacks'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'safe_query' => $sql,
                'error' => 'Database error (not SQL injection)'
            ];
        }
    }

    /**
     * Blind SQL Injection (취약한 버전)
     */
    private function vulnerableBlindInjection(string $payload): array
    {
        $sql = "SELECT COUNT(*) FROM users WHERE id = $payload";
        
        try {
            $pdo = $this->db->getConnection();
            $result = $pdo->query($sql);
            $count = $result ? $result->fetchColumn() : 0;

            return [
                'success' => true,
                'vulnerable_query' => $sql,
                'payload_injected' => $payload,
                'result' => $count,
                'boolean_result' => $count > 0,
                'educational_analysis' => [
                    'vulnerability_type' => 'Blind SQL Injection - Boolean Based',
                    'attack_method' => 'True/False responses reveal information',
                    'example_payloads' => [
                        "1 AND 1=1",
                        "1 AND 1=2", 
                        "1 AND (SELECT COUNT(*) FROM users) > 0",
                        "1 AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1) = 'a'"
                    ]
                ],
                'security_impact' => 'MEDIUM - Data can be extracted character by character'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'vulnerable_query' => $sql,
                'sql_error' => $e->getMessage(),
                'educational_note' => 'Blind injection syntax error reveals vulnerability'
            ];
        }
    }

    /**
     * 안전한 Blind 쿼리
     */
    private function safeBlindInjection(string $payload): array
    {
        $sql = "SELECT COUNT(*) FROM users WHERE id = ?";
        
        try {
            // 입력값 검증
            if (!is_numeric($payload)) {
                return [
                    'success' => false,
                    'error' => 'Invalid input - numeric value required',
                    'educational_note' => 'Input validation prevents injection attempts'
                ];
            }

            $pdo = $this->db->getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$payload]);
            $count = $stmt->fetchColumn();

            return [
                'success' => true,
                'safe_query' => $sql,
                'validated_input' => $payload,
                'result' => $count,
                'boolean_result' => $count > 0,
                'educational_analysis' => [
                    'protection_method' => 'Input Validation + Parameterized Query',
                    'validation_applied' => 'Numeric input validation',
                    'why_safe' => 'Invalid input rejected before reaching database'
                ],
                'security_impact' => 'NONE - Protected against blind injection'
            ];
        } catch (\PDOException $e) {
            return [
                'success' => false,
                'safe_query' => $sql,
                'error' => 'Database error (not SQL injection)'
            ];
        }
    }

    /**
     * Time-based Blind SQL Injection (취약한 버전)
     */
    private function vulnerableTimeBasedInjection(string $payload): array
    {
        $startTime = microtime(true);
        $sql = "SELECT * FROM users WHERE id = $payload";
        
        try {
            $pdo = $this->db->getConnection();
            $result = $pdo->query($sql);
            $data = $result ? $result->fetchAll(\PDO::FETCH_ASSOC) : [];
            $executionTime = microtime(true) - $startTime;

            return [
                'success' => true,
                'vulnerable_query' => $sql,
                'payload_injected' => $payload,
                'execution_time' => round($executionTime, 4),
                'data' => $data,
                'educational_analysis' => [
                    'vulnerability_type' => 'Time-based Blind SQL Injection',
                    'attack_method' => 'Database delays reveal information',
                    'example_payloads' => [
                        "1; WAITFOR DELAY '00:00:05'",
                        "1 AND (SELECT SLEEP(5))",
                        "1; SELECT pg_sleep(5)",
                        "1 AND IF(1=1, SLEEP(5), 0)"
                    ]
                ],
                'security_impact' => $executionTime > 1 ? 'HIGH - Time delay indicates injection success' : 'Injection attempted'
            ];
        } catch (\PDOException $e) {
            $executionTime = microtime(true) - $startTime;
            return [
                'success' => false,
                'vulnerable_query' => $sql,
                'sql_error' => $e->getMessage(),
                'execution_time' => round($executionTime, 4),
                'educational_note' => 'Time-based injection syntax error'
            ];
        }
    }

    /**
     * 안전한 Time-based 쿼리
     */
    private function safeTimeBasedInjection(string $payload): array
    {
        $startTime = microtime(true);
        $sql = "SELECT * FROM users WHERE id = ?";
        
        try {
            if (!is_numeric($payload)) {
                return [
                    'success' => false,
                    'error' => 'Invalid input - numeric value required',
                    'execution_time' => round(microtime(true) - $startTime, 4),
                    'educational_note' => 'Input validation prevents time-based attacks'
                ];
            }

            $pdo = $this->db->getConnection();
            $stmt = $pdo->prepare($sql);
            $stmt->execute([$payload]);
            $data = $stmt->fetchAll(\PDO::FETCH_ASSOC);
            $executionTime = microtime(true) - $startTime;

            return [
                'success' => true,
                'safe_query' => $sql,
                'validated_input' => $payload,
                'execution_time' => round($executionTime, 4),
                'data' => $data,
                'educational_analysis' => [
                    'protection_method' => 'Parameterized Query with Input Validation',
                    'timing_protection' => 'Consistent execution time regardless of input',
                    'why_safe' => 'No SQL code injection possible'
                ],
                'security_impact' => 'NONE - Protected against time-based injection'
            ];
        } catch (\PDOException $e) {
            $executionTime = microtime(true) - $startTime;
            return [
                'success' => false,
                'safe_query' => $sql,
                'error' => 'Database error (not SQL injection)',
                'execution_time' => round($executionTime, 4)
            ];
        }
    }

    /**
     * 테스트 데이터 초기화
     */
    private function initializeTestData(): void
    {
        try {
            $pdo = $this->db->getConnection();
            
            // 사용자 테이블 생성
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(20) DEFAULT 'user'
                )
            ");
            
            // 게시글 테이블 생성
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS articles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    content TEXT
                )
            ");
            
            // 테스트 데이터 삽입
            $pdo->exec("
                INSERT IGNORE INTO users (id, username, password, role) VALUES 
                (1, 'admin', 'admin123', 'admin'),
                (2, 'user1', 'password1', 'user'),
                (3, 'user2', 'password2', 'user'),
                (4, 'test', 'test123', 'user')
            ");
            
            $pdo->exec("
                INSERT IGNORE INTO articles (id, title, content) VALUES 
                (1, 'First Article', 'This is the first article content'),
                (2, 'Second Article', 'This is the second article content'),
                (3, 'Security Guide', 'How to prevent SQL injection attacks')
            ");
            
        } catch (\PDOException $e) {
            error_log("Failed to initialize SQL injection test data: " . $e->getMessage());
        }
    }
}