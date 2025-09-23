# WebSec-Lab v2 - Claude Code 프롬프트

## 📋 프로젝트 개요
**WebSec-Lab v2**는 WebGoat와 같은 실제 웹 보안 취약점 테스트 플랫폼입니다.
- **목적**: 실제 환경에서 웹 보안 취약점 학습 및 모의 침투 테스트
- **특징**: PHP, Node.js, Python, Java, Go 등 다중 언어 지원
- **실전형**: PayloadsAllTheThings 통합으로 실제 공격 페이로드 활용

## 🏗️ 프로젝트 구조
```
WebSec-Lab-v2/
├── servers/                     # 언어별 서버 구현
│   ├── php-server/              # PHP 서버 (포트: 8080)
│   ├── nodejs-server/           # Node.js 서버 (포트: 3000)
│   ├── python-server/           # Python 서버 (포트: 5000)
│   ├── java-server/             # Java 서버 (포트: 8081)
│   └── go-server/               # Go 서버 (포트: 8082)
├── database/                    # 데이터베이스 초기화 스크립트
├── docs/                        # 프로젝트 문서
├── scripts/                     # 유틸리티 스크립트
├── plans/                       # 개발 계획 및 설계 문서
└── tests/                       # 테스트 코드
```

## 🎯 현재 상태 (Phase 1 완료)
- ✅ Docker 환경 구축 완료
- ✅ PHP 서버 + SQL Injection 모듈 구현 완료
- ✅ 기본 프로젝트 구조 및 문서화 완료
- 🔄 Phase 2 준비 (XSS, Command Injection, 통합 대시보드)

## 🚀 다음 단계 목표
1. **Phase 2 개발**: XSS 취약점 모듈 구현 (모든 언어)
2. **통합 대시보드**: 언어별 취약점 비교 분석 UI
3. **Command Injection**: 운영체제 명령어 주입 취약점
4. **테스트 시스템**: 자동화된 취약점 테스트 프레임워크

## 🛠️ 주요 명령어
```bash
# 개발 환경 시작
make dev-up

# 전체 테스트 실행
make test-all

# 특정 서버 시작
make up-php    # PHP 서버만
make up-node   # Node.js 서버만

# 로그 확인
make logs
make logs-php
```

## 🔧 개발 시 주의사항

### 취약점 구현 원칙
- **실제 취약점**: 실제 공격이 성공하는 완전한 취약점 구현
- **다양한 시나리오**: 각기 다른 공격 벡터와 우회 기법 지원
- **실전 페이로드**: PayloadsAllTheThings의 실제 공격 페이로드 사용
- **언어별 특성**: 각 언어의 고유한 취약점 패턴 반영

### 코딩 컨벤션
- **코드 간결성**: 가독성을 위해 짧고 명확한 코드 작성 (함수당 10-20줄 권장)
- **최소 구현**: 필요한 기능만 구현, 과도한 추상화 지양
- **명확한 네이밍**: 변수/함수명만으로 기능 이해 가능하도록 작성
- **언어별 표준**: 각 언어의 표준 코딩 스타일 준수
- **API 통일**: 모든 서버가 동일한 API 구조 사용
- **에러 처리**: 상세한 로깅 및 에러 핸들링
- **문서화**: 모든 취약점에 대한 상세한 설명 포함

### 파일 구조 규칙
- `src/Controllers/`: API 엔드포인트 컨트롤러
- `src/Vulnerabilities/`: 취약점별 구현 클래스
- `src/Utils/`: 공통 유틸리티 (DB 연결 등)
- `tests/`: 각 취약점별 테스트 케이스

## 🧪 취약점 구현 가이드

### 1. 새로운 취약점 추가 시
```php
// 1. VulnerabilityInterface 구현
class NewVulnerability implements VulnerabilityInterface {
    public function executeVulnerable($payload, $params) {
        // 실제 취약점 코드 구현
        // 공격이 성공하도록 구현
    }

    public function executeSafe($payload, $params) {
        // 보안이 적용된 코드 구현
        // 동일한 기능이지만 안전하게 구현
    }
}

// 2. 컨트롤러에 엔드포인트 추가
// 3. 테스트 케이스 작성
// 4. 문서화
```

### 2. API 응답 형식
```json
{
    "success": true,
    "data": {
        "result": "실행 결과",
        "vulnerability_detected": true,
        "payload_used": "테스트 페이로드",
        "execution_time": "0.045s",
        "attack_success": true
    },
    "metadata": {
        "language": "php",
        "vulnerability_type": "sql_injection",
        "mode": "vulnerable"
    }
}
```

## 🎯 지원할 취약점 유형

### OWASP Top 10 기반
1. **Injection**: SQL, NoSQL, Command, LDAP 등
2. **Broken Authentication**: 세션 관리, 인증 우회
3. **Sensitive Data Exposure**: 정보 노출, 암호화 오류
4. **XML External Entities (XXE)**: XML 파싱 취약점
5. **Broken Access Control**: 권한 상승, 접근 제어 우회
6. **Security Misconfiguration**: 설정 오류 악용
7. **Cross-Site Scripting (XSS)**: 반사형, 저장형, DOM 기반
8. **Insecure Deserialization**: 직렬화 공격
9. **Components with Known Vulnerabilities**: 알려진 취약점
10. **Insufficient Logging & Monitoring**: 로깅 우회

### 언어별 특화 취약점
- **PHP**: Object Injection, File Inclusion, Type Juggling
- **Node.js**: Prototype Pollution, Path Traversal, Template Injection
- **Python**: Pickle Deserialization, Template Injection, Import Injection
- **Java**: Deserialization, Expression Language Injection
- **Go**: Template Injection, Race Conditions

## 📊 테스트 시스템

### 자동 테스트 실행
```bash
# 모든 취약점 테스트
php tests/run_tests.php

# 특정 취약점 테스트
php tests/run_tests.php sql_injection

# 실제 공격 시뮬레이션
php tests/run_tests.php sql_injection attack_mode
```

### 테스트 케이스 구조
- **공격 성공 케이스**: 취약점이 실제로 악용되는지 확인
- **방어 성공 케이스**: 보안 코드가 공격을 차단하는지 확인
- **우회 기법**: 다양한 필터링 우회 방법 테스트
- **페이로드 변형**: 인코딩, 난독화된 페이로드 테스트

## 🎯 Claude Code 작업 시 가이드

### 우선순위
1. **기존 코드 이해**: 현재 구조와 패턴 파악 후 일관성 유지
2. **실전 중심**: 실제 공격이 성공하는 완전한 취약점 구현
3. **문서화**: 모든 변경사항에 대한 명확한 설명
4. **테스트**: 구현과 동시에 공격 테스트 케이스 작성

### 구현 원칙
- 실제 침투 테스트에서 사용되는 기법 반영
- 다양한 공격 벡터와 우회 기법 지원
- 언어별 특성을 살린 고유 취약점 구현
- 실제 보안 도구(Burp Suite, SQLMap 등)와 호환되는 환경

### 코드 작성 가이드
- **간결함 우선**: 복잡한 로직보다는 명확하고 직관적인 코드
- **핵심 기능 집중**: 취약점 시연에 필요한 최소한의 코드만 작성
- **빠른 이해**: 5분 안에 코드 목적과 동작 방식을 파악할 수 있도록
- **실용적 예시**: 이론보다는 실제 동작하는 간단한 예제 중심

### 권장 사항
- 각 취약점마다 상세한 공격 시나리오 주석 추가
- 공격자 관점에서의 설명과 방어자 관점에서의 대응책 제시
- 언어별 특성을 살린 구현 방식
- 실제 CVE 사례와의 비교 설명

### 작업 완료 시 필수 절차
**🚨 모든 작업 완료 후 반드시 수행해야 할 절차:**
```bash
# 1. 변경사항 커밋
git add .
git commit -m "작업 내용 간략 설명

🤖 Generated with Claude Code"

# 2. 원격 저장소로 푸시
git push origin main
```

**중요**: 모든 개발 작업이 완료되면 반드시 git commit과 push를 수행하여 변경사항을 저장소에 반영해야 합니다. 이는 프로젝트 버전 관리와 팀 협업을 위해 필수적입니다.

---

이 프롬프트를 참고하여 WebSec-Lab v2 프로젝트를 실전적인 보안 테스트 플랫폼으로 발전시켜 주세요.