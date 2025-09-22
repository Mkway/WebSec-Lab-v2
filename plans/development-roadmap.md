# WebSec-Lab v2 개발 로드맵

## 📊 현재 상태
- ✅ **Phase 1 완료**: Docker 환경, PHP 서버, SQL Injection 모듈
- 🔄 **Phase 2 준비**: XSS, Command Injection, 통합 대시보드

## 🎯 Phase 2 목표 (다음 2-3주)

### 1. XSS (Cross-Site Scripting) 구현
**우선순위**: 높음 🔴
**예상 소요**: 1주

#### 서버별 구현 계획
- **PHP 서버** (1-2일)
  - Reflected XSS: GET/POST 파라미터 반영
  - Stored XSS: 데이터베이스 저장 후 출력
  - DOM-based XSS: JavaScript 기반 취약점
  - 필터 우회: 다양한 인코딩 및 난독화 기법

- **Node.js 서버** (1-2일)
  - Express 템플릿 엔진 취약점
  - JSON 기반 XSS
  - Template Injection 연계

- **Python 서버** (1-2일)
  - Flask/Django 템플릿 취약점
  - Jinja2 Template Injection
  - JSON Response XSS

#### 구현할 XSS 시나리오
```javascript
// 1. 기본 Reflected XSS
http://localhost:8080/xss/reflected?input=<script>alert('XSS')</script>

// 2. Stored XSS (게시판)
POST /xss/stored
{
  "username": "<script>alert('Stored XSS')</script>",
  "comment": "Normal comment"
}

// 3. DOM XSS
http://localhost:8080/xss/dom#<img src=x onerror=alert('DOM XSS')>

// 4. 필터 우회
http://localhost:8080/xss/reflected?input=<svg/onload=alert('Bypass')>
```

### 2. Command Injection 구현
**우선순위**: 높음 🔴
**예상 소요**: 3-4일

#### 언어별 특성 반영
- **PHP**: `exec()`, `system()`, `shell_exec()` 취약점
- **Node.js**: `child_process.exec()` 취약점
- **Python**: `os.system()`, `subprocess` 취약점

#### 구현할 시나리오
```bash
# 1. 기본 Command Injection
POST /cmd/ping
{
  "host": "127.0.0.1; cat /etc/passwd"
}

# 2. Blind Command Injection
POST /cmd/ping
{
  "host": "127.0.0.1; sleep 10"
}

# 3. 필터 우회
POST /cmd/ping
{
  "host": "127.0.0.1$(cat /etc/passwd)"
}
```

### 3. 통합 대시보드 개발
**우선순위**: 중간 🟡
**예상 소요**: 1주

#### 기능 요구사항
- **언어별 비교**: 동일 취약점의 언어별 동작 비교
- **페이로드 테스터**: 실시간 페이로드 테스트
- **결과 분석**: 성공/실패 통계 및 로그
- **PayloadsAllTheThings 통합**: 카테고리별 페이로드 탐색

#### 기술 스택
- **Frontend**: Vue.js 3 + Tailwind CSS
- **Backend**: PHP (기존 구조 활용)
- **API**: RESTful API (언어별 서버 통합)

## 🎯 Phase 3 목표 (1개월 후)

### 1. Advanced 취약점 구현
- **File Upload**: 악성 파일 업로드 취약점
- **Directory Traversal**: 경로 조작 공격
- **CSRF**: Cross-Site Request Forgery
- **SSTI**: Server-Side Template Injection

### 2. 언어별 특화 취약점
- **PHP**: Object Injection, File Inclusion, Type Juggling
- **Node.js**: Prototype Pollution, Package 취약점
- **Python**: Pickle Deserialization, Import Injection
- **Java**: Deserialization, Expression Language Injection
- **Go**: Race Conditions, Template Injection

### 3. 모니터링 시스템
- **실시간 로그**: 공격 시도 실시간 모니터링
- **알림 시스템**: 특정 패턴 탐지 시 알림
- **통계 대시보드**: 공격 성공률, 시간별 분석

## 🛠️ 구현 방법론

### 1. TDD (Test-Driven Development)
```bash
# 1. 테스트 케이스 작성
php tests/XSSTest.php

# 2. 최소 구현
# 3. 리팩토링
# 4. 통합 테스트
```

### 2. 페이로드 검증 시스템
```php
class PayloadValidator {
    public function validateXSS($payload) {
        // XSS 페이로드 유효성 검사
    }

    public function validateCommandInjection($payload) {
        // Command Injection 페이로드 검사
    }
}
```

### 3. 언어간 일관성 유지
```json
// 모든 언어에서 동일한 API 구조
{
    "endpoint": "/vulnerabilities/{type}",
    "methods": ["POST"],
    "parameters": {
        "payload": "string",
        "mode": "vulnerable|safe",
        "options": "object"
    }
}
```

## 📋 작업 순서

### Week 1: XSS 구현
- **Day 1-2**: PHP XSS 모듈 구현
- **Day 3-4**: Node.js XSS 모듈 구현
- **Day 5-6**: Python XSS 모듈 구현
- **Day 7**: 테스트 및 문서화

### Week 2: Command Injection
- **Day 1-2**: PHP Command Injection 구현
- **Day 3-4**: Node.js Command Injection 구현
- **Day 5-6**: Python Command Injection 구현
- **Day 7**: 테스트 및 문서화

### Week 3: 통합 대시보드
- **Day 1-3**: Frontend 대시보드 개발
- **Day 4-5**: API 통합
- **Day 6-7**: 테스트 및 최적화

## 🎯 성공 지표
- [ ] 모든 언어에서 XSS 취약점 정상 동작
- [ ] Command Injection 페이로드 95% 이상 성공률
- [ ] 통합 대시보드에서 실시간 비교 가능
- [ ] PayloadsAllTheThings 페이로드 100% 호환
- [ ] 자동 테스트 커버리지 80% 이상

---

이 로드맵을 기반으로 체계적이고 실전적인 웹 보안 테스트 플랫폼을 구축해나가겠습니다.