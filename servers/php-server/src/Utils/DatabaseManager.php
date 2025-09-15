<?php

namespace WebSecLab\Utils;

/**
 * Database Manager
 * 데이터베이스 연결 관리 (싱글톤 패턴)
 */
class DatabaseManager
{
    private static ?DatabaseManager $instance = null;
    private ?\PDO $connection = null;
    
    private string $host;
    private string $dbname;
    private string $username;
    private string $password;
    private int $port;

    private function __construct()
    {
        $this->host = $_ENV['DB_HOST'] ?? 'mysql';
        $this->dbname = $_ENV['DB_NAME'] ?? 'websec_php';
        $this->username = $_ENV['DB_USER'] ?? 'websec';
        $this->password = $_ENV['DB_PASS'] ?? 'websec123';
        $this->port = (int)($_ENV['DB_PORT'] ?? 3306);
    }

    /**
     * 싱글톤 인스턴스 반환
     */
    public static function getInstance(): DatabaseManager
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * 데이터베이스 연결 반환
     */
    public function getConnection(): \PDO
    {
        if ($this->connection === null) {
            $this->connect();
        }
        return $this->connection;
    }

    /**
     * 데이터베이스 연결
     */
    private function connect(): void
    {
        try {
            $dsn = "mysql:host={$this->host};port={$this->port};dbname={$this->dbname};charset=utf8mb4";
            
            $options = [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES => false, // 실제 prepared statements 사용
                \PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ];

            $this->connection = new \PDO($dsn, $this->username, $this->password, $options);
            
            // 데이터베이스 초기화
            $this->initializeDatabase();
            
        } catch (\PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new \Exception("Database connection failed: " . $e->getMessage());
        }
    }

    /**
     * 데이터베이스 초기화
     */
    private function initializeDatabase(): void
    {
        try {
            // 취약점 테스트를 위한 기본 테이블들 생성
            $this->createTables();
            $this->insertSampleData();
        } catch (\PDOException $e) {
            error_log("Database initialization failed: " . $e->getMessage());
        }
    }

    /**
     * 테이블 생성
     */
    private function createTables(): void
    {
        $tables = [
            // 사용자 테이블
            'users' => "
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(50) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    email VARCHAR(100),
                    role VARCHAR(20) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_username (username),
                    INDEX idx_role (role)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ",
            
            // 게시글 테이블
            'articles' => "
                CREATE TABLE IF NOT EXISTS articles (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(200) NOT NULL,
                    content TEXT,
                    author_id INT,
                    category VARCHAR(50),
                    published BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_title (title),
                    INDEX idx_category (category),
                    INDEX idx_published (published)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ",
            
            // 제품 테이블 (e-commerce 시뮬레이션)
            'products' => "
                CREATE TABLE IF NOT EXISTS products (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    description TEXT,
                    price DECIMAL(10,2),
                    category_id INT,
                    stock_quantity INT DEFAULT 0,
                    active BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_name (name),
                    INDEX idx_price (price),
                    INDEX idx_category (category_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ",
            
            // 댓글 테이블
            'comments' => "
                CREATE TABLE IF NOT EXISTS comments (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    article_id INT,
                    user_id INT,
                    content TEXT NOT NULL,
                    parent_id INT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    FOREIGN KEY (parent_id) REFERENCES comments(id) ON DELETE CASCADE,
                    INDEX idx_article (article_id),
                    INDEX idx_user (user_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ",
            
            // 로그 테이블
            'access_logs' => "
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NULL,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    request_uri TEXT,
                    request_method VARCHAR(10),
                    response_code INT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_user_id (user_id),
                    INDEX idx_ip (ip_address),
                    INDEX idx_created_at (created_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            "
        ];

        foreach ($tables as $tableName => $sql) {
            $this->connection->exec($sql);
        }
    }

    /**
     * 샘플 데이터 삽입
     */
    private function insertSampleData(): void
    {
        // 사용자 데이터
        $this->connection->exec("
            INSERT IGNORE INTO users (id, username, password, email, role) VALUES 
            (1, 'admin', 'admin123', 'admin@example.com', 'admin'),
            (2, 'user1', 'password1', 'user1@example.com', 'user'),
            (3, 'user2', 'password2', 'user2@example.com', 'user'),
            (4, 'test', 'test123', 'test@example.com', 'user'),
            (5, 'john_doe', 'john123', 'john@example.com', 'user'),
            (6, 'jane_smith', 'jane456', 'jane@example.com', 'moderator'),
            (7, 'bob_wilson', 'bob789', 'bob@example.com', 'user')
        ");

        // 게시글 데이터
        $this->connection->exec("
            INSERT IGNORE INTO articles (id, title, content, author_id, category, published) VALUES 
            (1, 'Welcome to WebSec Lab', 'This is an educational platform for learning web security vulnerabilities.', 1, 'general', TRUE),
            (2, 'SQL Injection Basics', 'Understanding how SQL injection attacks work and how to prevent them.', 1, 'security', TRUE),
            (3, 'Cross-Site Scripting (XSS)', 'Learn about different types of XSS attacks and mitigation strategies.', 6, 'security', TRUE),
            (4, 'Secure Coding Practices', 'Best practices for writing secure web applications.', 6, 'development', TRUE),
            (5, 'OWASP Top 10 2021', 'Overview of the most critical web application security risks.', 1, 'security', TRUE),
            (6, 'Authentication and Authorization', 'Implementing proper access controls in web applications.', 6, 'security', TRUE),
            (7, 'Draft Article', 'This article is still being written...', 2, 'general', FALSE)
        ");

        // 제품 데이터
        $this->connection->exec("
            INSERT IGNORE INTO products (id, name, description, price, category_id, stock_quantity) VALUES 
            (1, 'Security Handbook', 'Comprehensive guide to web application security', 29.99, 1, 100),
            (2, 'Penetration Testing Kit', 'Tools and resources for ethical hacking', 79.99, 2, 50),
            (3, 'Secure Development Course', 'Online course on secure coding practices', 149.99, 3, 999),
            (4, 'Vulnerability Scanner', 'Automated security testing tool', 299.99, 2, 25),
            (5, 'Cryptography Textbook', 'Advanced cryptographic algorithms and implementations', 59.99, 1, 75)
        ");

        // 댓글 데이터
        $this->connection->exec("
            INSERT IGNORE INTO comments (id, article_id, user_id, content, parent_id) VALUES 
            (1, 1, 2, 'Great introduction to the platform!', NULL),
            (2, 1, 3, 'Looking forward to learning more about security.', NULL),
            (3, 2, 4, 'Very informative article about SQL injection.', NULL),
            (4, 2, 5, 'Could you add more examples?', NULL),
            (5, 2, 1, 'Thanks for the feedback! I\\'ll add more examples soon.', 4),
            (6, 3, 7, 'XSS is such a common vulnerability. Thanks for explaining it clearly.', NULL)
        ");

        // 액세스 로그 샘플 데이터
        $this->connection->exec("
            INSERT IGNORE INTO access_logs (id, user_id, ip_address, user_agent, request_uri, request_method, response_code) VALUES 
            (1, 1, '192.168.1.100', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', '/login', 'POST', 200),
            (2, 2, '192.168.1.101', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36', '/articles', 'GET', 200),
            (3, NULL, '192.168.1.102', 'curl/7.68.0', '/vulnerabilities/sql-injection', 'POST', 200),
            (4, 3, '192.168.1.103', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36', '/products', 'GET', 200)
        ");
    }

    /**
     * 연결 해제 방지 (싱글톤)
     */
    private function __clone() {}
    
    /**
     * 직렬화 방지 (싱글톤)
     */
    public function __wakeup()
    {
        throw new \Exception("Cannot unserialize a singleton.");
    }

    /**
     * 연결 종료
     */
    public function closeConnection(): void
    {
        $this->connection = null;
    }

    /**
     * 트랜잭션 시작
     */
    public function beginTransaction(): bool
    {
        return $this->getConnection()->beginTransaction();
    }

    /**
     * 트랜잭션 커밋
     */
    public function commit(): bool
    {
        return $this->getConnection()->commit();
    }

    /**
     * 트랜잭션 롤백
     */
    public function rollback(): bool
    {
        return $this->getConnection()->rollback();
    }

    /**
     * 데이터베이스 정보 반환
     */
    public function getDatabaseInfo(): array
    {
        try {
            $pdo = $this->getConnection();
            $version = $pdo->query("SELECT VERSION() as version")->fetch()['version'];
            $charset = $pdo->query("SELECT @@character_set_database as charset")->fetch()['charset'];
            
            return [
                'host' => $this->host,
                'database' => $this->dbname,
                'version' => $version,
                'charset' => $charset,
                'connection_status' => 'connected'
            ];
        } catch (\Exception $e) {
            return [
                'host' => $this->host,
                'database' => $this->dbname,
                'connection_status' => 'failed',
                'error' => $e->getMessage()
            ];
        }
    }
}