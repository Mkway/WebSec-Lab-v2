# WebSec-Lab v2 🛡️

**차세대 멀티 언어 웹 보안 취약점 테스트 플랫폼**

## 🚀 빠른 시작

### XSS 테스트 바로 시작 (추천)
```bash
make xss
```
**→ PHP 서버 + MySQL + Redis 실행**
**→ 접속: http://localhost:8080**

### 다른 실행 옵션
```bash
make php      # PHP 서버만
make nodejs   # Node.js 서버만
make python   # Python 서버만
make java     # Java 서버만
make go       # Go 서버만
make all      # 모든 서버 + 데이터베이스
```

## 🧪 XSS 테스트 실행

### 자동 테스트 (53개 테스트)
```bash
make test-xss
```

### API 테스트
```bash
# 기본 XSS 테스트
curl -X POST http://localhost:8080/vulnerabilities/xss \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "<script>alert(\"XSS\")</script>",
    "mode": "both"
  }'

# 페이로드 목록
curl http://localhost:8080/vulnerabilities/xss/payloads

# 시나리오 목록
curl http://localhost:8080/vulnerabilities/xss/scenarios
```

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

## 🎓 현재 지원하는 취약점

### ✅ 구현 완료
- **XSS (Cross-Site Scripting)** (PHP) - 완전 구현 ✨
  - Reflected XSS (4가지 시나리오)
  - 17개 실전 페이로드 포함
  - 취약한/안전한 코드 비교
  - 53개 자동 테스트 (100% 성공률)

- **SQL Injection** (PHP) - PayloadsAllTheThings 기반
  - Authentication Bypass
  - UNION Based Injection
  - Blind SQL Injection (Boolean/Time-based)
  - Error Based Injection

### 🔄 다음 단계 (Phase 2)
- **XSS** - 다른 언어 (Node.js, Python, Java, Go)
- **Command Injection** - 모든 언어
- **File Upload Vulnerabilities** - 모든 언어
- **Directory Traversal** - 모든 언어

### 📋 계획된 취약점
- CSRF, SSTI, XXE, SSRF, NoSQL Injection
- Language-specific vulnerabilities (PHP Object Injection, Node.js Prototype Pollution, etc.)

## 🛠️ 관리 명령어

### 🎯 주요 명령어
```bash
make help      # 도움말
make status    # 컨테이너 상태 확인
make logs      # 실시간 로그 보기
make stop      # 모든 컨테이너 중지
make clean     # 완전 정리
make restart   # 빠른 재시작
```

### 🧪 테스트 명령어
```bash
make test-xss  # XSS 테스트 실행 (53개 테스트)
make test-api  # API 테스트 실행
```

## 🌐 접속 주소

| 서비스 | URL | 상태 |
|--------|-----|------|
| **PHP 서버** | http://localhost:8080 | ✅ XSS 완전 구현 |
| **Node.js 서버** | http://localhost:3000 | 🔄 구현 예정 |
| **Python 서버** | http://localhost:5000 | 🔄 구현 예정 |
| **Java 서버** | http://localhost:8081 | 🔄 구현 예정 |
| **Go 서버** | http://localhost:8082 | 🔄 구현 예정 |

## 🎭 XSS 테스트 시나리오

- **basic**: 기본 출력
- **search**: 검색 결과 페이지
- **greeting**: 사용자 인사말
- **form**: 폼 입력 결과

## 💣 XSS 페이로드 예시

```javascript
// 기본 스크립트
<script>alert("XSS")</script>

// 이미지 태그
<img src=x onerror=alert("XSS")>

// SVG 태그
<svg onload=alert("XSS")>

// 속성 우회
" onmouseover="alert('XSS')" "

// 대소문자 우회
<ScRiPt>alert("XSS")</ScRiPt>
```

## 📊 데이터베이스 구성

- **MySQL**: PHP, Java, Go 서버용 관계형 데이터
- **PostgreSQL**: Python 서버용 고급 SQL 기능
- **MongoDB**: Node.js, Python 서버용 NoSQL 데이터
- **Redis**: 세션 캐시 및 임시 데이터 저장

## 🧪 XSS 테스트 결과

```bash
🛡️  XSS 테스트 프레임워크 시작
📋 XSS 테스트 실행 중...

🔍 기본 XSS 테스트 - ✅ 성공
🎭 시나리오별 테스트 - ✅ 성공
💣 페이로드 테스트 - ✅ 성공
🛡️ 방어 메커니즘 테스트 - ✅ 성공
🔓 우회 기법 테스트 - ✅ 성공

📊 테스트 결과:
   총 테스트: 53
   성공: 53
   실패: 0
   성공률: 100.0%

🎉 모든 테스트가 성공했습니다!
```

## 🔒 보안 주의사항

⚠️ **경고**: 이 프로젝트는 **교육 목적으로만** 사용해야 합니다.

- 🚫 **프로덕션 환경에서 사용 금지**
- 🚫 **공개 네트워크에 노출 금지**
- ✅ **격리된 로컬 환경에서만 사용**
- ✅ **학습 및 연구 목적으로만 사용**

## 🚀 개발 로드맵

### Phase 1 (완료) ✅
- [x] Docker 환경 구축
- [x] 언어별 서버 기본 구조
- [x] SQL Injection 모듈 구현 (PHP)
- [x] XSS 모듈 완전 구현 (PHP) ✨

### Phase 2 (진행 중) 🔄
- [ ] XSS 모듈 구현 (Node.js, Python, Java, Go)
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

### v2.1.0 (2024-09-22)
- 🎉 **XSS 모듈 완전 구현** (PHP)
- ✅ 53개 테스트 100% 성공
- 🧪 자동화된 테스트 프레임워크 구축
- 🐳 Docker 환경 통합 및 정리
- 📋 프로파일 기반 실행 시스템

### v2.0.0-alpha (2024-01-15)
- 🎉 초기 프로젝트 구조 완성
- ✅ Docker Compose 환경 구축
- ✅ PHP 서버 + SQL Injection 모듈 구현
- ✅ MySQL, PostgreSQL, MongoDB 초기화
- ✅ PayloadsAllTheThings 통합
- 📚 기본 문서화 완료