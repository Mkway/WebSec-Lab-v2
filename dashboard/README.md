# WebSec-Lab v2 - Dashboard

## 🎯 개요
Vue.js의 복잡함을 제거하고 **순수 HTML + CSS + JavaScript**로 구현한 메인 대시보드입니다.

## 🐳 Docker 환경
현재 대시보드는 두 가지 Docker 설정을 지원합니다:
- **Nginx 서버** (Dockerfile): 프로덕션 환경용
- **Python HTTP 서버** (Dockerfile.local): 개발 환경용 (현재 사용 중)

## 📁 구조
```
dashboard/
├── index.html                    # 메인 HTML 파일
├── css/
│   └── style.css                # CSS 스타일 (900+ 줄)
├── js/
│   ├── app.js                   # 메인 JavaScript 로직
│   ├── vulnerability-renderer.js # 취약점 분석 렌더링
│   └── comparison-renderer.js    # 비교 분석 렌더링
├── Dockerfile                   # Nginx 프로덕션 설정
├── Dockerfile.local             # Python 개발 서버 설정 (현재 사용)
├── nginx.conf                   # Nginx 설정 파일
└── README.md                    # 이 문서
```

## 🚀 실행 방법

### 1. Docker Compose로 실행 (권장)
```bash
# 전체 환경 시작
make dev-up

# 또는 직접 Docker Compose 실행
docker-compose up -d
```

### 2. 브라우저에서 접속
```
http://localhost  # 포트 80
```

### 3. 로컬 개발 서버 (선택사항)
```bash
cd dashboard
python3 -m http.server 8090
```

## ✨ 주요 기능

### 🔧 언어 선택
- PHP (포트 8080)
- Node.js (포트 3000)
- Python (포트 5000)
- Java (포트 8081)
- Go (포트 8082)

### 🎯 취약점 테스트
- **SQL Injection**: 다양한 페이로드 지원, 쿼리 분석
- **XSS**: 크로스사이트 스크립팅 테스트, 실시간 실행
- **비교 분석**: 취약한 코드 vs 안전한 코드 동시 테스트
- **상세한 분석**: 공격 성공/실패, 코드 비교, 보안 권장사항

### 🛡️ 테스트 모드
- 취약한 코드만
- 안전한 코드만
- 둘 다 비교

### 📊 실시간 서버 상태
- 자동 서버 상태 확인
- 실시간 연결 상태 표시

## 🎨 UI 특징

### 🌈 현대적 디자인
- 그라데이션 배경
- 반응형 레이아웃
- 부드러운 애니메이션

### 📱 모바일 친화적
- 완전 반응형 디자인
- 터치 친화적 버튼

### ⚡ 빠른 로딩
- 외부 의존성 최소화
- 인라인 스타일 및 스크립트

## 🔧 기술 스택
- **HTML5**: 시맨틱 마크업
- **CSS3**: Grid, Flexbox, 애니메이션 (900+ 줄)
- **Vanilla JavaScript**: ES6+ 문법, 모듈화된 구조
- **Fetch API**: 비동기 HTTP 요청
- **Docker**: Python HTTP 서버 (포트 80)
- **실시간 분석**: 취약한 코드 vs 안전한 코드 비교

## 📋 기존 Vue.js와 비교

| 항목 | Vue.js 대시보드 | 현재 대시보드 |
|------|-----------------|---------------|
| 파일 수 | 15+ 파일 | 6 파일 |
| 코드 라인 수 | 800+ 줄 | 1200+ 줄 |
| 의존성 | Vue, Bootstrap, Prism | 없음 |
| 빌드 과정 | 필요 | 불필요 |
| 디버깅 | 복잡 | 간단 |
| 학습 곡선 | 가파름 | 평탄함 |
| 분석 기능 | 기본 | 상세한 비교 분석 |

## 🎯 사용법

### SQL Injection 테스트
1. 언어 선택 (예: PHP)
2. 취약점 유형: "SQL Injection" 선택
3. 빠른 페이로드 버튼 클릭 또는 직접 입력
4. "테스트 실행" 버튼 클릭

### XSS 테스트
1. 언어 선택 (예: Node.js)
2. 취약점 유형: "XSS" 선택
3. XSS 페이로드 입력
4. "테스트 실행" 버튼 클릭

## 🛠️ 커스터마이징

### 새로운 취약점 유형 추가
1. `index.html`에 새 취약점 사이드바 아이템 추가
2. `app.js`의 `PAYLOADS` 객체에 페이로드 추가
3. `vulnerability-renderer.js`에 분석 로직 추가
4. `comparison-renderer.js`에 비교 렌더링 로직 추가

### 스타일 수정
- `css/style.css`에서 색상, 레이아웃 등 수정 가능
- CSS 변수로 테마 색상 관리
- 반응형 디자인 지원

### Docker 설정 변경
- `Dockerfile.local`: Python 서버 (개발용, 현재 사용)
- `Dockerfile`: Nginx 서버 (프로덕션용)
- `docker-compose.yml`에서 설정 변경 가능

## 🔍 디버깅
1. 브라우저 개발자 도구 열기 (F12)
2. Console 탭에서 로그 확인
3. Network 탭에서 API 요청/응답 확인

## 🔧 개발 환경
- **Docker 볼륨 마운트**: 실시간 파일 변경 반영
- **브라우저 새로고침**: 변경사항 즉시 확인 가능
- **포트**: 80번 (Docker Compose 환경)

## 📈 향후 개선사항
- [ ] Command Injection 지원
- [ ] File Upload 취약점 지원
- [ ] 테스트 결과 히스토리
- [ ] 페이로드 즐겨찾기 기능
- [ ] 실시간 서버 모니터링 개선
- [ ] 취약점 분석 리포트 내보내기