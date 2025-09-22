# WebSec-Lab v2 프레젠테이션 슬라이드

## 📌 슬라이드 1: 타이틀 슬라이드
**제목**: WebSec-Lab v2 - 멀티 언어 웹 보안 테스트 플랫폼
**부제**: 현재 구현 상태 및 실행 환경 소개
**발표자**: [발표자명]
**날짜**: 2024년 9월 22일

---

## 📌 슬라이드 2: 프로젝트 개요
### 🎯 WebSec-Lab v2란?
- **차세대 멀티 언어 웹 보안 취약점 테스트 플랫폼**
- 교육 목적의 안전한 로컬 환경
- 실제 공격 시나리오를 통한 실전 학습

### ✨ 주요 특징
- 🌐 **멀티 언어 지원**: PHP, Node.js, Python, Java, Go
- 🔍 **실시간 비교**: 언어별 취약점 동작 방식 분석
- 🛡️ **PayloadsAllTheThings 통합**: 실제 공격 페이로드 활용
- 🐳 **Docker 기반**: 쉬운 설치 및 격리된 환경

---

## 📌 슬라이드 3: 현재 구현 상태
### ✅ 완료된 기능
- **XSS (Cross-Site Scripting)** - PHP 서버 완전 구현
  - 4가지 시나리오 (basic, search, greeting, form)
  - 17개 실전 페이로드 포함
  - 53개 자동 테스트 (100% 성공률)

- **SQL Injection** - PHP 서버 구현
  - Authentication Bypass
  - UNION Based / Blind SQL Injection
  - Error Based Injection

### 🔄 진행 중
- XSS 모듈 다른 언어 확장 (Node.js, Python, Java, Go)
- Command Injection 구현
- 통합 대시보드 개발

---

## 📌 슬라이드 4: 아키텍처 다이어그램
```
┌─────────────────────────────────────────────────────────────┐
│                    Frontend Dashboard                        │
│                     (Nginx + HTML)                          │
│                        Port: 80                             │
└─────────────────────┬───────────────────────────────────────┘
                     │ HTTP API
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼────┐  ┌───▼────┐  ┌───▼────┐  ┌───▼────┐  ┌───▼────┐
│  PHP   │  │Node.js │  │ Python │  │  Java  │  │   Go   │
│  App   │  │ Express│  │ Flask  │  │Spring  │  │  Gin   │
│ :8080  │  │ :3000  │  │ :5000  │  │ :8081  │  │ :8082  │
└────────┘  └────────┘  └────────┘  └────────┘  └────────┘
     │           │           │           │           │
┌────▼───┐  ┌───▼────┐  ┌───▼─────┐  ┌──▼─────┐  ┌──▼─────┐
│ MySQL  │  │MongoDB │  │PostgreSQL│  │ MySQL  │  │ MySQL  │
│ :3307  │  │ :27017 │  │  :5432   │  │ :3307  │  │ :3307  │
└────────┘  └────────┘  └──────────┘  └────────┘  └────────┘
             ┌─────────────────────────────────────────────┐
             │              Redis Cache                     │
             │                :6379                        │
             └─────────────────────────────────────────────┘
```

---

## 📌 슬라이드 5: 현재 실행 환경
### 🚀 실행 중인 서비스
| 서비스 | 이미지 | 포트 | 상태 |
|--------|--------|------|------|
| **대시보드** | websec-lab-v2-dashboard | 80 | ✅ 정상 |
| **PHP 서버** | websec-lab-v2-php-server | 8080 | ✅ 정상 |
| **MySQL** | mysql:8.0 | 3307 | ✅ 정상 |
| **Redis** | redis:7-alpine | 6379 | ✅ 정상 |

### 📊 리소스 사용량
- **컨테이너 수**: 4개
- **네트워크**: websec-network (172.20.0.0/16)
- **볼륨**: mysql_data, redis_data

---

## 📌 슬라이드 6: XSS 구현 세부사항
### 🎭 테스트 시나리오
1. **Basic**: 기본 HTML 출력
2. **Search**: 검색 결과 페이지 렌더링
3. **Greeting**: 사용자 인사말 표시
4. **Form**: 폼 데이터 처리 결과

### 💣 페이로드 예시
```javascript
// 기본 스크립트 태그
<script>alert("XSS")</script>

// 이미지 태그 이벤트 핸들러
<img src=x onerror=alert("XSS")>

// SVG 태그
<svg onload=alert("XSS")>

// 속성 이스케이프 우회
" onmouseover="alert('XSS')" "

// 대소문자 우회
<ScRiPt>alert("XSS")</ScRiPt>
```

---

## 📌 슬라이드 7: API 엔드포인트
### 🔌 현재 구현된 API
```bash
GET  /health
GET  /vulnerabilities
POST /vulnerabilities/{type}
POST /vulnerabilities/xss
GET  /vulnerabilities/xss/payloads
GET  /vulnerabilities/xss/scenarios
```

### 📝 API 응답 예시
```json
{
  "success": true,
  "data": {
    "result": "실행 결과",
    "vulnerability_detected": true,
    "payload_used": "<script>alert('XSS')</script>",
    "execution_time": "0.045s",
    "attack_success": true
  },
  "metadata": {
    "language": "php",
    "vulnerability_type": "xss",
    "mode": "vulnerable"
  }
}
```

---

## 📌 슬라이드 8: 테스트 결과
### 🧪 XSS 자동 테스트 현황
```
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
```

---

## 📌 슬라이드 9: 구현 과정
### 📅 개발 단계
1. **Phase 1 (완료)** ✅
   - Docker 환경 구축
   - PHP 서버 기본 구조
   - SQL Injection 모듈 구현
   - XSS 모듈 완전 구현

2. **Phase 2 (진행 중)** 🔄
   - XSS 다른 언어 확장
   - Command Injection 구현
   - 통합 대시보드 개발

3. **Phase 3 (계획)** 📋
   - File Upload 취약점
   - Directory Traversal
   - CSRF 보호 우회

---

## 📌 슬라이드 10: 기술 스택
### 🛠️ 사용된 기술
**프론트엔드**
- HTML5, CSS3, JavaScript
- Bootstrap 5.3
- Font Awesome

**백엔드**
- PHP 8.2 (Apache)
- Node.js (Express) - 계획
- Python (Flask) - 계획
- Java (Spring Boot) - 계획
- Go (Gin) - 계획

**데이터베이스**
- MySQL 8.0
- PostgreSQL 15
- MongoDB 6.0
- Redis 7

**인프라**
- Docker & Docker Compose
- Nginx (리버스 프록시)

---

## 📌 슬라이드 11: 보안 고려사항
### 🔒 보안 원칙
⚠️ **중요**: 교육 목적으로만 사용

**격리 환경**
- 🚫 프로덕션 환경 사용 금지
- 🚫 공개 네트워크 노출 금지
- ✅ 로컬 Docker 환경만 사용
- ✅ 학습 및 연구 목적

**네트워크 보안**
- 내부 Docker 네트워크 사용
- 포트 격리 (localhost만 접근)
- 컨테이너 간 통신 제한

---

## 📌 슬라이드 12: 데모 실행 방법
### 🚀 빠른 시작
```bash
# 1. 저장소 클론
git clone https://github.com/[repo]/WebSec-Lab-v2.git
cd WebSec-Lab-v2

# 2. XSS 테스트 환경 시작
make xss

# 3. 브라우저에서 접속
http://localhost       # 대시보드
http://localhost:8080  # PHP 서버

# 4. API 테스트
curl -X POST http://localhost:8080/vulnerabilities/xss \
  -H "Content-Type: application/json" \
  -d '{"payload":"<script>alert(\"XSS\")</script>","mode":"both"}'
```

---

## 📌 슬라이드 13: 향후 계획
### 🎯 단기 목표 (1-2개월)
- 🌐 XSS 모듈 모든 언어 확장
- 💉 Command Injection 구현
- 📊 실시간 비교 대시보드

### 🎯 중기 목표 (3-6개월)
- 📁 File Upload 취약점
- 🗂️ Directory Traversal
- 🔐 CSRF 보호 우회
- 🔍 SSTI (Server-Side Template Injection)

### 🎯 장기 목표 (6개월+)
- 🤖 AI 기반 취약점 탐지
- 📈 실시간 모니터링
- 🎓 교육 과정 통합
- 🌍 다국어 지원

---

## 📌 슬라이드 14: 질문 및 토론
### 💬 토론 주제
1. **언어별 취약점 특성 차이는?**
2. **실제 환경과의 차이점은?**
3. **교육적 활용 방안은?**
4. **추가하고 싶은 기능은?**

### 📧 연락처
- **GitHub**: [저장소 링크]
- **Email**: [이메일 주소]
- **문서**: `/docs` 폴더 참조

---

## 🎯 참고사항
- 모든 코드는 GitHub에서 확인 가능
- Docker 환경으로 누구나 쉽게 실행
- PayloadsAllTheThings 데이터베이스 활용
- 지속적인 업데이트 및 개선 예정