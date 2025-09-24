# S_WEB_Project - 프로젝트 요약

## 🏗️ **프로젝트 구조**
- **websec-lab/src/**: 메인 웹 애플리케이션 (PHP 기반)
- **webhacking/**: 취약점 테스트 모듈 (81개 파일, 18,881줄)
- **database/**: MongoDB, PostgreSQL, Redis 연결 클래스
- **g_mcp_auto_setting/**: MCP 자동 설정 파일
- **node_app/**: Node.js 기반 직렬화 테스트 환경
- **CLAUDE.md**: 개발 워크플로우 및 커밋 규칙
- **index.php**: 메인 게시판 (582줄, SQL Injection 취약점 교육용)
- **VulnerabilityDashboard.php**: 취약점 테스트 대시보드 (247줄)
- **login/register/admin**: 사용자 관리 시스템
- **style.css**: Bootstrap 5 기반 UI 스타일링

## 🎯 **핵심 기능**
- **취약점 테스트 플랫폼**: 21개 취약점 유형 테스트 환경
- **실제 공격 실행**: 시뮬레이션이 아닌 실제 취약점 실행
- **교육용 설계**: 취약한 코드 vs 안전한 코드 비교 표시
- **다중 데이터베이스**: MySQL, MongoDB, PostgreSQL, Redis 지원
- **게시판 시스템**: 글 작성, 검색, 페이지네이션, 알림
- **사용자 관리**: 로그인, 회원가입, 권한 관리
- **파일 업로드**: 위험한 파일 업로드 테스트
- **API 보안**: REST API, GraphQL, JWT 테스트
- **실시간 로깅**: 보안 이벤트 및 공격 시도 로깅
- **대시보드**: 테스트 결과 통계 및 분석
- **모바일 대응**: Bootstrap 5 반응형 디자인
- **VULNERABILITY_MODE**: 교육용 취약점 활성화 모드
- **보안 권장사항**: 각 테스트별 보안 가이드 제공
- **다국어 인터페이스**: 한국어 기본, 영어 지원
- **Docker 지원**: 컨테이너 기반 배포 환경

## 🔧 **구현된 취약점 테스트**

### **기본 우선순위 (8개)**
- **SQL Injection**: UNION, Boolean, Time-based, Error-based
- **XSS**: Reflected, Stored, DOM-based, Filter Bypass
- **Command Injection**: 시스템 명령어 실행 및 우회 기법
- **File Upload**: 악성 파일 업로드 및 실행
- **CSRF**: 요청 위조 및 토큰 우회
- **Directory Traversal**: 경로 순회 공격
- **File Inclusion (LFI/RFI)**: 로컬/원격 파일 포함
- **Authentication Bypass**: 인증 우회 기법

### **중간 우선순위 (5개)**
- **XXE**: XML 외부 엔티티 공격
- **SSRF**: 서버측 요청 위조
- **SSTI**: 서버 사이드 템플릿 인젝션
- **Open Redirect**: 오픈 리다이렉트 공격
- **XPath Injection**: XPath 쿼리 조작

### **고급 환경 (8개)**
- **NoSQL Injection**: MongoDB 인젝션
- **Cache Injection**: Redis 캐시 조작
- **Java Deserialization**: Node.js 환경 RCE
- **Business Logic**: 비즈니스 로직 우회
- **Race Condition**: 동시성 취약점
- **Advanced Deserialization**: 다중 언어 직렬화
- **API Security**: 종합 API 보안 테스트
- **Reverse Proxy Misconfiguration**: 프록시 설정 오류

## 💻 **기술 스택**
- **Backend**: PHP 7.4+, MySQL, MongoDB, PostgreSQL, Redis
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Additional**: Node.js 18+ (Java deserialization)
- **Database ORM**: PDO (PHP Data Objects)
- **Session Management**: PHP Sessions
- **File Handling**: 멀티파트 업로드, 파일 유효성 검사
- **Security**: 입력 검증, 출력 인코딩, CSRF 토큰
- **Logging**: 보안 이벤트 로깅 시스템
- **Testing**: 실제 공격 실행 + 안전한 구현 비교
- **Deployment**: Apache/Nginx, Docker 컨테이너 지원

## 🛡️ **보안 교육 기능**
- **이중 모드**: VULNERABILITY_MODE 토글
- **실행 결과 비교**: 취약한 코드 vs 안전한 코드
- **보안 권장사항**: 각 취약점별 대응 방법
- **페이로드 다양성**: 각 테스트당 5-15개 페이로드
- **실시간 알림**: 공격 시도 감지 및 로깅
- **색상 코딩**: 취약/안전 결과 시각적 구분
- **실행 시간 측정**: 공격 성능 분석
- **사용자별 통계**: 개인 테스트 이력 관리
- **관리자 도구**: 전체 시스템 모니터링
- **API 문서**: REST API 명세 및 테스트
- **GraphQL**: 스키마 조작 및 인증 우회
- **JWT 분석**: 토큰 조작 및 알고리즘 공격
- **NoSQL 쿼리**: 다양한 NoSQL 인젝션 기법
- **캐시 조작**: Redis 데이터 오염 공격
- **템플릿 엔진**: Twig, Smarty 인젝션

## 📊 **개발 현황**
- **총 파일**: 81개 PHP 파일, 18,881줄 코드
- **완료된 모듈**: 21개 취약점 테스트
- **진행 상황**: 고급 모듈 개발 중
- **코드 구조**: MVC 패턴, 모듈화 설계
- **데이터베이스**: 8개 테이블, 관계형 설계
- **사용자 인터페이스**: 반응형 웹 디자인
- **테스트 커버리지**: 모든 OWASP Top 10 포함
- **문서화**: 개발 가이드, API 문서, 보안 명세
- **버전 관리**: Git, 상세한 커밋 메시지
- **배포 환경**: 개발/테스트/운영 분리
- **모니터링**: 로그 분석, 성능 측정
- **보안 강화**: 입력 검증, 출력 인코딩
- **확장성**: 플러그인 아키텍처
- **국제화**: 다국어 지원 구조
- **접근성**: WCAG 2.1 준수

---

*이 문서는 리팩토링 전 프로젝트 상태를 요약한 것입니다.*
*생성일: 2025-09-23*