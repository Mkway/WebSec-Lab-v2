# WebSec-Lab v2 🛡️

**차세대 멀티 언어 웹 보안 취약점 테스트 플랫폼**

## 📋 프로젝트 개요

WebSec-Lab v2는 로컬 환경에서 다양한 프로그래밍 언어의 웹 보안 취약점을 안전하게 학습하고 테스트할 수 있는 통합 플랫폼입니다.

### 🎯 주요 목표
- **멀티 언어 지원**: PHP, Node.js, Python, Java, Go 등 다양한 언어 환경
- **실시간 비교**: 언어별 취약점 동작 방식 비교 분석
- **교육적 목적**: 안전한 로컬 환경에서의 보안 학습
- **확장성**: 새로운 언어와 취약점 쉽게 추가 가능
- **PayloadsAllTheThings 통합**: 실제 공격 페이로드 데이터베이스 활용

## 🏗️ 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Dashboard                        │
│                     (PHP + Vue.js)                          │
└─────────────────────┬───────────────────────────────────────┘
                     │ API Gateway
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼────┐  ┌───▼────┐  ┌───▼────┐  ┌───▼────┐  ┌───▼────┐
│  PHP   │  │Node.js │  │ Python │  │  Java  │  │   Go   │
│  App   │  │ Express│  │ Flask  │  │Spring  │  │  Gin   │
│ :8080  │  │ :3000  │  │ :5000  │  │ :8081  │  │ :8082  │
└────────┘  └────────┘  └────────┘  └────────┘  └────────┘
```

## 🚀 빠른 시작

### 1. 환경 요구사항
- Docker & Docker Compose
- Git
- 최소 8GB RAM 권장

### 2. 프로젝트 실행
```bash
# 저장소 클론
git clone <repository-url>
cd websec-lab-v2

# 환경 설정
cp .env.example .env

# 컨테이너 빌드 및 실행
make up

# 또는
docker-compose up -d
```

### 3. 접속
- **통합 대시보드**: http://localhost
- **PHP 서버**: http://localhost:8080
- **Node.js 서버**: http://localhost:3000
- **Python 서버**: http://localhost:5000
- **Java 서버**: http://localhost:8081
- **Go 서버**: http://localhost:8082

## 🎓 현재 지원하는 취약점 (Phase 1)

### ✅ 구현 완료
- **SQL Injection** (PHP) - PayloadsAllTheThings 기반
  - Authentication Bypass
  - UNION Based Injection
  - Blind SQL Injection (Boolean/Time-based)
  - Error Based Injection

### 🔄 진행 중 (다음 단계)
- **XSS (Cross-Site Scripting)** - 모든 언어
- **Command Injection** - 모든 언어
- **File Upload Vulnerabilities** - 모든 언어
- **Directory Traversal** - 모든 언어

### 📋 계획된 취약점
- CSRF, SSTI, XXE, SSRF, NoSQL Injection
- Language-specific vulnerabilities (PHP Object Injection, Node.js Prototype Pollution, etc.)

## 🛠️ 개발 명령어

```bash
# 모든 서버 시작
make up

# 개발 모드로 시작 (핫 리로드)
make dev-up

# 특정 언어 서버만 시작
make up-php
make up-node
make up-python

# 로그 확인
make logs
make logs-php

# 테스트 실행
make test-all

# 환경 정리
make clean
```

## 🧪 사용 예시

### SQL Injection 테스트 (PHP 서버)
```bash
# 취약한 코드 테스트
curl -X POST http://localhost:8080/vulnerabilities/sql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "'\'' OR '\''1'\''='\''1",
    "mode": "vulnerable",
    "parameters": {
      "test_type": "login",
      "target": "username"
    }
  }'

# 안전한 코드 테스트
curl -X POST http://localhost:8080/vulnerabilities/sql-injection \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "'\'' OR '\''1'\''='\''1",
    "mode": "safe",
    "parameters": {
      "test_type": "login",
      "target": "username"
    }
  }'
```

### 서버 헬스체크
```bash
curl http://localhost:8080/health
```

## 📊 데이터베이스 구성

- **MySQL**: PHP, Java, Go 서버용 관계형 데이터
- **PostgreSQL**: Python 서버용 고급 SQL 기능
- **MongoDB**: Node.js, Python 서버용 NoSQL 데이터
- **Redis**: 세션 캐시 및 임시 데이터 저장

## 🔒 보안 주의사항

⚠️ **경고**: 이 프로젝트는 **교육 목적으로만** 사용해야 합니다.

- 🚫 **프로덕션 환경에서 사용 금지**
- 🚫 **공개 네트워크에 노출 금지**
- ✅ **격리된 로컬 환경에서만 사용**
- ✅ **학습 및 연구 목적으로만 사용**

## 📖 문서

- [📐 시스템 아키텍처](docs/architecture/system-architecture.md)
- [🐳 Docker 구성](docs/deployment/docker-setup.md)
- [🔧 개발 가이드](docs/development/development-guide.md)
- [🌐 API 문서](docs/api/api-reference.md)
- [🏗️ 프로젝트 구조](docs/architecture/project-structure.md)
- [🎯 취약점 우선순위](VULNERABILITY_PRIORITY.md)

## 🚀 개발 로드맵

### Phase 1 (완료) ✅
- [x] Docker 환경 구축
- [x] 언어별 서버 기본 구조
- [x] SQL Injection 모듈 구현 (PHP)
- [x] 데이터베이스 초기화 스크립트

### Phase 2 (진행 중) 🔄
- [ ] XSS 모듈 구현 (모든 언어)
- [ ] Command Injection 모듈 구현
- [ ] 통합 대시보드 개발
- [ ] 크로스 언어 비교 기능

### Phase 3 (계획) 📋
- [ ] File Upload 취약점
- [ ] Directory Traversal
- [ ] CSRF 보호 우회
- [ ] 모니터링 시스템

## 🤝 기여하기

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 교육 목적으로 MIT 라이선스 하에 배포됩니다.

## 🙏 감사의 말

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) - 실제 공격 페이로드 데이터베이스
- OWASP 프로젝트
- 각 언어별 보안 커뮤니티
- 오픈소스 보안 도구들

---

**WebSec-Lab v2** - 안전한 환경에서 배우는 웹 보안 🛡️

---

## 📝 변경 이력

### v2.0.0-alpha (2024-01-15)
- 🎉 초기 프로젝트 구조 완성
- ✅ Docker Compose 환경 구축
- ✅ PHP 서버 + SQL Injection 모듈 구현
- ✅ MySQL, PostgreSQL, MongoDB 초기화
- ✅ PayloadsAllTheThings 통합
- 📚 기본 문서화 완료