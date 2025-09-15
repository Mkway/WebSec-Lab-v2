# 시스템 아키텍처 설계서 🏗️

## 📋 개요

WebSec-Lab v2는 마이크로서비스 기반의 멀티 언어 웹 보안 테스트 플랫폼으로 설계되었습니다. 각 프로그래밍 언어별로 독립적인 서버를 운영하면서도, 통합된 대시보드를 통해 일관된 사용자 경험을 제공합니다.

## 🎯 설계 원칙

### 1. 언어별 격리 (Language Isolation)
- 각 언어는 독립적인 컨테이너에서 실행
- 언어별 특화된 취약점과 라이브러리 지원
- 한 언어의 문제가 다른 언어에 영향을 주지 않음

### 2. 확장성 (Scalability)
- 새로운 언어 추가가 용이한 플러그인 아키텍처
- 표준화된 API 인터페이스
- Docker 기반 컨테이너 오케스트레이션

### 3. 교육적 목적 (Educational Focus)
- 취약한 코드와 안전한 코드의 명확한 비교
- 언어별 차이점과 공통점 시각화
- 실시간 테스트 결과 분석

## 🏗️ 전체 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                        Client (Browser)                         │
└─────────────────────┬───────────────────────────────────────────┘
                     │ HTTP/HTTPS
┌─────────────────────▼───────────────────────────────────────────┐
│                    Nginx Load Balancer                          │
│                        (Port 80/443)                           │
└─────────────────────┬───────────────────────────────────────────┘
                     │
┌─────────────────────▼───────────────────────────────────────────┐
│                  Dashboard Service (PHP)                        │
│                      (Main Interface)                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              Multi-Language Test Controller                 ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐││
│  │  │   PHP   │ │ Node.js │ │ Python  │ │  Java   │ │   Go    │││
│  │  │ Client  │ │ Client  │ │ Client  │ │ Client  │ │ Client  │││
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────┬───────────────────────────────────────────┘
                     │ Internal API Calls
     ┌───────────────┼───────────────┬───────────────┬───────────────┐
     │               │               │               │               │
┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐ ┌────▼────┐
│   PHP   │ │ Node.js │ │ Python  │ │  Java   │ │   Go    │
│ Server  │ │ Server  │ │ Server  │ │ Server  │ │ Server  │
│ :8080   │ │ :3000   │ │ :5000   │ │ :8081   │ │ :8082   │
└────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘
     │           │           │           │           │
     └───────────┼───────────┼───────────┼───────────┘
                 │           │           │
    ┌────────────┼───────────┼───────────┼────────────┐
    │            │           │           │            │
┌───▼───┐ ┌─────▼─────┐ ┌───▼───┐ ┌────▼────┐ ┌─────▼─────┐
│ MySQL │ │PostgreSQL │ │MongoDB│ │  Redis  │ │  Shared   │
│       │ │           │ │       │ │         │ │ Storage   │
│:3306  │ │   :5432   │ │:27017 │ │  :6379  │ │           │
└───────┘ └───────────┘ └───────┘ └─────────┘ └───────────┘
```

## 🔧 컴포넌트 상세 설계

### 1. Frontend Dashboard (통합 대시보드)

#### 기술 스택
- **Backend**: PHP 8.2 + Custom MVC Framework
- **Frontend**: Vue.js 3 + Bootstrap 5
- **API**: RESTful JSON API

#### 주요 기능
```php
┌─────────────────────────────────────────────┐
│            Dashboard Controller             │
├─────────────────────────────────────────────┤
│ • runCrossLanguageTest()                    │
│ • getLanguageServerStatus()                 │
│ • compareVulnerabilityResults()             │
│ • generateTestReport()                      │
└─────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│         Multi-Language Client               │
├─────────────────────────────────────────────┤
│ • PHPServerClient                           │
│ • NodeJSServerClient                        │
│ • PythonServerClient                        │
│ • JavaServerClient                          │
│ • GoServerClient                            │
└─────────────────────────────────────────────┘
```

#### API 엔드포인트
```
GET  /api/servers/status           # 모든 언어 서버 상태
POST /api/test/cross-language      # 크로스 언어 테스트 실행
GET  /api/test/results/{id}        # 테스트 결과 조회
POST /api/test/compare             # 언어별 결과 비교
```

### 2. Language Servers (언어별 서버)

#### 표준 API 인터페이스
모든 언어 서버는 동일한 API 규격을 따릅니다:

```json
POST /vulnerabilities/{vulnerability-type}
Content-Type: application/json

{
  "payload": "1' OR '1'='1",
  "mode": "vulnerable|safe",
  "parameters": {
    "target": "username",
    "context": "login"
  }
}

Response:
{
  "language": "php",
  "vulnerability": "sql-injection",
  "payload": "1' OR '1'='1",
  "mode": "vulnerable",
  "result": {
    "success": true,
    "data": [...],
    "execution_time": 0.023,
    "affected_rows": 3
  },
  "analysis": {
    "risk_level": "high",
    "attack_type": "authentication_bypass",
    "impact": "Full database access"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### PHP Server 구조
```php
servers/php-server/
├── Dockerfile
├── composer.json
├── public/
│   ├── index.php                    # 메인 엔트리포인트
│   └── .htaccess
├── src/
│   ├── Controllers/
│   │   ├── VulnerabilityController.php
│   │   └── BaseController.php
│   ├── Vulnerabilities/
│   │   ├── SQLInjection.php         # SQL 인젝션 구현
│   │   ├── XSS.php                  # XSS 구현
│   │   ├── ObjectInjection.php      # PHP 객체 인젝션
│   │   └── FileInclusion.php        # LFI/RFI 구현
│   ├── Models/
│   │   ├── TestResult.php
│   │   └── VulnerabilityTest.php
│   └── Utils/
│       ├── DatabaseManager.php
│       └── PayloadValidator.php
└── config/
    └── database.php
```

#### Node.js Server 구조
```javascript
servers/nodejs-server/
├── Dockerfile
├── package.json
├── server.js                       # Express 서버
├── routes/
│   ├── vulnerabilities.js          # 취약점 라우팅
│   └── health.js                    # 헬스체크
├── controllers/
│   ├── vulnerabilityController.js
│   └── baseController.js
├── vulnerabilities/
│   ├── prototypePollution.js       # 프로토타입 오염
│   ├── commandInjection.js         # 명령어 인젝션
│   ├── nosqlInjection.js           # NoSQL 인젝션
│   └── deserialization.js          # JSON/객체 역직렬화
├── models/
│   ├── TestResult.js
│   └── VulnerabilityTest.js
└── utils/
    ├── databaseManager.js
    └── payloadValidator.js
```

### 3. Database Layer (데이터베이스 계층)

#### 데이터베이스 역할 분담
```
┌─────────────────────────────────────────────┐
│                MySQL                        │
├─────────────────────────────────────────────┤
│ • 사용자 인증 데이터                          │
│ • 테스트 세션 관리                           │
│ • SQL 인젝션 테스트 데이터                   │
│ • 언어별 서버 설정                           │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│              PostgreSQL                     │
├─────────────────────────────────────────────┤
│ • 고급 SQL 인젝션 테스트                     │
│ • JSON/JSONB 데이터 타입 테스트              │
│ • 복잡한 쿼리 성능 테스트                    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│               MongoDB                       │
├─────────────────────────────────────────────┤
│ • NoSQL 인젝션 테스트 데이터                 │
│ • 테스트 결과 로그 저장                      │
│ • 사용자 세션 데이터                         │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│                Redis                        │
├─────────────────────────────────────────────┤
│ • 세션 캐시                                 │
│ • 테스트 결과 임시 저장                      │
│ • 서버 간 메시지 큐                          │
│ • 레이트 리미팅                             │
└─────────────────────────────────────────────┘
```

## 🔄 데이터 플로우

### 1. 크로스 언어 테스트 플로우
```
Client Request
     │
     ▼
Dashboard (PHP)
     │
     ├─ Validate Request
     ├─ Parse Target Languages
     └─ Generate Test ID
     │
     ▼
Multi-Language Client
     │
     ├─ PHP Server Call      ──► PHP Response
     ├─ Node.js Server Call  ──► Node.js Response
     ├─ Python Server Call   ──► Python Response
     ├─ Java Server Call     ──► Java Response
     └─ Go Server Call       ──► Go Response
     │
     ▼
Result Aggregator
     │
     ├─ Normalize Responses
     ├─ Compare Results
     └─ Generate Analysis
     │
     ▼
Dashboard Response
     │
     ▼
Client Display
```

### 2. 개별 언어 테스트 플로우
```
Language Server Request
     │
     ▼
Vulnerability Controller
     │
     ├─ Validate Payload
     ├─ Select Mode (vulnerable/safe)
     └─ Load Vulnerability Class
     │
     ▼
Vulnerability Executor
     │
     ├─ Execute Vulnerable Code    (if mode=vulnerable)
     ├─ Execute Safe Code          (if mode=safe)
     └─ Capture Results
     │
     ▼
Result Analyzer
     │
     ├─ Analyze Risk Level
     ├─ Identify Attack Type
     └─ Calculate Impact
     │
     ▼
Database Logger
     │
     ├─ Store Test Result
     └─ Update Statistics
     │
     ▼
JSON Response
```

## 🛡️ 보안 고려사항

### 1. 컨테이너 격리
- 각 언어 서버는 독립적인 Docker 컨테이너에서 실행
- 네트워크 격리를 통한 lateral movement 방지
- 리소스 제한으로 DoS 공격 방지

### 2. 데이터 보호
- 테스트 데이터는 실제 프로덕션 데이터와 완전 분리
- 민감한 정보는 환경 변수로 관리
- 임시 데이터는 자동 정리

### 3. 접근 제어
- 로컬 네트워크에서만 접근 가능
- 포트별 방화벽 규칙 적용
- 기본 인증 메커니즘 제공

## 📊 성능 최적화

### 1. 캐싱 전략
```
┌─────────────────────────────────────────────┐
│              Redis Cache                    │
├─────────────────────────────────────────────┤
│ • 테스트 결과 캐싱 (1시간)                   │
│ • 자주 사용되는 페이로드 캐싱                │
│ • 서버 상태 캐싱 (30초)                     │
│ • 사용자 세션 캐싱                          │
└─────────────────────────────────────────────┘
```

### 2. 리소스 관리
- 컨테이너별 메모리/CPU 제한
- 데이터베이스 연결 풀링
- 비동기 요청 처리

### 3. 확장성 고려
- 언어 서버 수평 확장 지원
- 로드 밸런싱 설정
- 자동 헬스체크 및 복구

## 🔧 개발 환경 설정

### 1. 로컬 개발
```bash
# 개발 모드로 실행
docker-compose -f docker-compose.dev.yml up -d

# 핫 리로드 활성화
docker-compose exec php-server composer install --dev
docker-compose exec nodejs-server npm run dev
```

### 2. 디버깅
- Xdebug (PHP)
- Node.js Inspector
- 각 언어별 디버거 설정

### 3. 테스팅
```bash
# 전체 테스트 스위트 실행
make test-all

# 언어별 테스트
make test-php
make test-nodejs
make test-python
```

이 아키텍처는 확장성, 유지보수성, 교육적 가치를 모두 고려하여 설계되었습니다.