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
            // SQLite 사용으로 변경 (MySQL 의존성 제거)
            $dbPath = '/tmp/websec_php.sqlite';
            $dsn = "sqlite:{$dbPath}";

            $options = [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES => false
            ];

            $this->connection = new \PDO($dsn, null, null, $options);
            
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
            // 사용자 테이블 (SQLite 버전)
            'users' => "
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    email TEXT,
                    role TEXT DEFAULT 'user',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ",

            // 기본 테이블만 생성 (SQLite 버전)
            'articles' => "
                CREATE TABLE IF NOT EXISTS articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    content TEXT,
                    author_id INTEGER,
                    category TEXT,
                    published INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
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
        // SQLite에서는 INSERT OR IGNORE 사용
        // 사용자 데이터
        $this->connection->exec("
            INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES
            (1, 'admin', 'admin123', 'admin@example.com', 'admin'),
            (2, 'user1', 'password1', 'user1@example.com', 'user'),
            (3, 'test', 'test123', 'test@example.com', 'user')
        ");

        // 게시글 데이터
        $this->connection->exec("
            INSERT OR IGNORE INTO articles (id, title, content, author_id, category, published) VALUES
            (1, 'Welcome to WebSec Lab', 'Educational platform for learning web security.', 1, 'general', 1),
            (2, 'SQL Injection Basics', 'Understanding how SQL injection attacks work.', 1, 'security', 1)
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