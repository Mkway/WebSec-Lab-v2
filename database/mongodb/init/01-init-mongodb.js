// WebSec-Lab v2 MongoDB 초기화 스크립트

// Admin 사용자로 인증
db = db.getSiblingDB('admin');
db.auth('admin', 'admin123');

// WebSec 데이터베이스들 생성 및 초기화
var databases = ['websec_nodejs', 'websec_python', 'websec_java', 'websec_test'];

databases.forEach(function(dbName) {
    print('Initializing database: ' + dbName);
    
    // 데이터베이스 선택/생성
    db = db.getSiblingDB(dbName);
    
    // 컬렉션 생성 및 인덱스 설정
    
    // 1. 취약점 테스트 결과 컬렉션
    db.createCollection('vulnerability_tests');
    db.vulnerability_tests.createIndex({ "test_id": 1 }, { unique: true });
    db.vulnerability_tests.createIndex({ "vulnerability_type": 1 });
    db.vulnerability_tests.createIndex({ "language": 1 });
    db.vulnerability_tests.createIndex({ "mode": 1 });
    db.vulnerability_tests.createIndex({ "created_at": 1 });
    
    // 2. 사용자 컬렉션 (NoSQL Injection 테스트용)
    db.createCollection('users');
    db.users.createIndex({ "username": 1 }, { unique: true });
    db.users.createIndex({ "email": 1 }, { unique: true });
    db.users.createIndex({ "role": 1 });
    
    // 3. 제품 컬렉션
    db.createCollection('products');
    db.products.createIndex({ "name": 1 });
    db.products.createIndex({ "category": 1 });
    db.products.createIndex({ "price": 1 });
    db.products.createIndex({ "tags": 1 });
    
    // 4. 로그 컬렉션
    db.createCollection('logs');
    db.logs.createIndex({ "timestamp": 1 });
    db.logs.createIndex({ "level": 1 });
    db.logs.createIndex({ "source": 1 });
    
    // 5. 세션 컬렉션
    db.createCollection('sessions');
    db.sessions.createIndex({ "session_id": 1 }, { unique: true });
    db.sessions.createIndex({ "user_id": 1 });
    db.sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });
    
    // 6. 댓글 컬렉션 (중첩 문서 테스트용)
    db.createCollection('comments');
    db.comments.createIndex({ "post_id": 1 });
    db.comments.createIndex({ "user_id": 1 });
    db.comments.createIndex({ "created_at": 1 });
    
    // 샘플 데이터 삽입
    print('Inserting sample data for: ' + dbName);
    
    // 사용자 데이터
    db.users.insertMany([
        {
            "_id": ObjectId(),
            "username": "admin",
            "password": "admin123",
            "email": "admin@example.com",
            "role": "admin",
            "profile": {
                "full_name": "Administrator",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            },
            "permissions": ["read", "write", "admin", "delete"],
            "created_at": new Date(),
            "last_login": new Date()
        },
        {
            "_id": ObjectId(),
            "username": "testuser",
            "password": "password123",
            "email": "test@example.com",
            "role": "user",
            "profile": {
                "full_name": "Test User",
                "age": 25,
                "country": "US"
            },
            "permissions": ["read"],
            "created_at": new Date(),
            "last_login": new Date()
        },
        {
            "_id": ObjectId(),
            "username": "analyst",
            "password": "analyst123",
            "email": "analyst@example.com",
            "role": "analyst",
            "profile": {
                "full_name": "Security Analyst",
                "department": "Security",
                "clearance_level": "high"
            },
            "permissions": ["read", "write", "analyze"],
            "created_at": new Date(),
            "last_login": new Date()
        },
        {
            "_id": ObjectId(),
            "username": "guest",
            "password": "guest",
            "email": "guest@example.com",
            "role": "guest",
            "profile": {
                "full_name": "Guest User"
            },
            "permissions": ["read"],
            "created_at": new Date(),
            "temporary": true
        }
    ]);
    
    // 제품 데이터  
    db.products.insertMany([
        {
            "_id": ObjectId(),
            "name": "Security Scanner Pro",
            "description": "Advanced vulnerability scanning tool",
            "price": 299.99,
            "category": "security_tools",
            "tags": ["security", "scanning", "automation"],
            "features": {
                "scan_types": ["web", "network", "database"],
                "supported_languages": ["PHP", "JavaScript", "Python", "Java"],
                "integrations": ["Jenkins", "GitLab", "JIRA"]
            },
            "stock": 100,
            "active": true,
            "created_at": new Date()
        },
        {
            "_id": ObjectId(),
            "name": "Penetration Testing Kit",
            "description": "Complete toolkit for ethical hacking",
            "price": 199.99,
            "category": "tools",
            "tags": ["pentesting", "hacking", "tools"],
            "features": {
                "tools_included": ["nmap", "burp", "metasploit"],
                "documentation": "comprehensive",
                "support": "24/7"
            },
            "stock": 50,
            "active": true,
            "created_at": new Date()
        },
        {
            "_id": ObjectId(),
            "name": "Secure Coding Guide",
            "description": "Best practices for secure software development",
            "price": 49.99,
            "category": "books",
            "tags": ["education", "secure_coding", "best_practices"],
            "features": {
                "pages": 500,
                "languages_covered": ["PHP", "JavaScript", "Python", "Java", "C#"],
                "includes_examples": true
            },
            "stock": 200,
            "active": true,
            "created_at": new Date()
        }
    ]);
    
    // 로그 데이터
    db.logs.insertMany([
        {
            "_id": ObjectId(),
            "timestamp": new Date(),
            "level": "INFO",
            "source": "api",
            "message": "User authentication successful",
            "details": {
                "user_id": "admin",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        },
        {
            "_id": ObjectId(),
            "timestamp": new Date(),
            "level": "WARN",
            "source": "security",
            "message": "Multiple failed login attempts detected",
            "details": {
                "ip_address": "192.168.1.200",
                "attempts": 5,
                "timeframe": "5 minutes"
            }
        },
        {
            "_id": ObjectId(),
            "timestamp": new Date(),
            "level": "ERROR",
            "source": "database",
            "message": "Connection timeout",
            "details": {
                "database": "primary",
                "timeout_duration": "30s",
                "retry_count": 3
            }
        }
    ]);
    
    // 댓글 데이터 (중첩 구조)
    db.comments.insertMany([
        {
            "_id": ObjectId(),
            "post_id": "article_1",
            "user_id": "testuser",
            "content": "Great article about SQL injection!",
            "replies": [
                {
                    "user_id": "admin",
                    "content": "Thanks for the feedback!",
                    "timestamp": new Date()
                },
                {
                    "user_id": "analyst",
                    "content": "Very informative indeed.",
                    "timestamp": new Date()
                }
            ],
            "likes": 5,
            "created_at": new Date()
        },
        {
            "_id": ObjectId(),
            "post_id": "article_2",
            "user_id": "analyst",
            "content": "Could you add more examples of NoSQL injection?",
            "replies": [],
            "likes": 2,
            "created_at": new Date()
        }
    ]);
    
    // 세션 데이터
    var expirationDate = new Date();
    expirationDate.setHours(expirationDate.getHours() + 24); // 24시간 후 만료
    
    db.sessions.insertMany([
        {
            "_id": ObjectId(),
            "session_id": "sess_" + Math.random().toString(36).substr(2, 9),
            "user_id": "admin",
            "data": {
                "role": "admin",
                "permissions": ["read", "write", "admin", "delete"],
                "last_activity": new Date()
            },
            "expires_at": expirationDate,
            "created_at": new Date()
        },
        {
            "_id": ObjectId(),
            "session_id": "sess_" + Math.random().toString(36).substr(2, 9),
            "user_id": "testuser",
            "data": {
                "role": "user",
                "permissions": ["read"],
                "last_activity": new Date()
            },
            "expires_at": expirationDate,
            "created_at": new Date()
        }
    ]);
    
    print('Database ' + dbName + ' initialized successfully');
});

// 모니터링을 위한 추가 컬렉션 생성
db = db.getSiblingDB('websec_test');

// 서버 메트릭스 컬렉션
db.createCollection('server_metrics');
db.server_metrics.createIndex({ "server_name": 1 });
db.server_metrics.createIndex({ "timestamp": 1 });

// 초기 서버 메트릭스 데이터
db.server_metrics.insertMany([
    {
        "_id": ObjectId(),
        "server_name": "nodejs-server",
        "timestamp": new Date(),
        "metrics": {
            "cpu_usage": 15.5,
            "memory_usage": 45.2,
            "response_time": 35.5,
            "active_connections": 25,
            "requests_per_minute": 120
        },
        "status": "healthy"
    },
    {
        "_id": ObjectId(),
        "server_name": "python-server",
        "timestamp": new Date(),
        "metrics": {
            "cpu_usage": 12.3,
            "memory_usage": 38.7,
            "response_time": 42.1,
            "active_connections": 18,
            "requests_per_minute": 95
        },
        "status": "healthy"
    }
]);

// 집계 파이프라인 예시 (성능 테스트용)
print('Creating aggregation pipeline examples...');

// 사용자별 활동 통계 파이프라인
db.user_activity_stats = function() {
    return db.logs.aggregate([
        {
            $match: {
                "details.user_id": { $exists: true }
            }
        },
        {
            $group: {
                _id: "$details.user_id",
                total_activities: { $sum: 1 },
                last_activity: { $max: "$timestamp" },
                activity_types: { $addToSet: "$source" }
            }
        },
        {
            $sort: { total_activities: -1 }
        }
    ]);
};

// 제품 카테고리별 통계 파이프라인
db.product_category_stats = function() {
    return db.products.aggregate([
        {
            $group: {
                _id: "$category",
                total_products: { $sum: 1 },
                avg_price: { $avg: "$price" },
                total_stock: { $sum: "$stock" },
                active_products: {
                    $sum: { $cond: ["$active", 1, 0] }
                }
            }
        },
        {
            $sort: { total_products: -1 }
        }
    ]);
};

print('MongoDB initialization completed successfully!');
print('Available databases: ' + databases.join(', '));
print('Use db.user_activity_stats() and db.product_category_stats() for analytics');