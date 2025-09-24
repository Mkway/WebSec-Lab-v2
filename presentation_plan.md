# WebSec-Lab-v2 프로젝트 발표 계획

이 문서는 프로젝트 발표(PPT) 자료를 만들 때 어떤 내용을 어떤 순서로 구성하면 좋을지에 대한 가이드입니다.

---

### **Slide 1: 제목 슬라이드**

*   **프로젝트 명**: WebSec-Lab-v2
*   **부제**: 다양한 웹 취약점 학습을 위한 Polyglot 실습 환경
*   **발표자**: (발표자 이름)
*   **날짜**: (발표 날짜)

---

### **Slide 2: 프로젝트 소개 (Introduction)**

*   **문제 제기**: 왜 웹 보안(Web Security) 학습이 중요한가?
    *   증가하는 웹 기반 서비스와 비례하여 늘어나는 보안 위협
    *   개발자들이 코딩 단계에서부터 보안을 고려해야 할 필요성 증대
*   **기존 학습 방식의 어려움**:
    *   안전한 실습 환경을 직접 구축하기의 번거로움
    *   다양한 유형의 취약점을 체계적으로 경험하기 어려움
*   **프로젝트 목표**:
    *   **"안전하고 통제된 환경에서 다양한 웹 취약점을 직접 실습하고 그 원리를 이해하는 학습 플랫폼을 제공한다."**

---

### **Slide 3: 시스템 아키텍처 (System Architecture)**

*   **핵심**: **마이크로서비스 아키텍처** 기반으로 설계
    *   언어별로 독립된 서버를 운영하여 유연성 및 확장성 확보
*   **주요 구성 요소**:
    *   **Dashboard (Nginx)**: 사용자가 모든 취약점 실습을 이용하는 단일 진입점 (UI 제공 및 리버스 프록시)
    *   **Backend Servers (Polyglot)**: `Python`, `PHP`, `Node.js`, `Java`, `Go` 등 다양한 언어로 구현된 취약점 API 서버
    *   **Databases**: `MySQL`, `PostgreSQL`, `MongoDB` 등 각 서버가 사용하는 데이터베이스
*   **(팁)**: `docker-compose.yml`의 서비스 관계를 바탕으로 간단한 아키텍처 다이어그램을 그려서 보여주면 이해도를 높일 수 있습니다.

---

### **Slide 4: 사용된 기술 스택 (Technology Stack)**

*   **Frontend**: `HTML`, `CSS`, `JavaScript`
*   **Backend**: `Python (Flask)`, `PHP`, `Node.js (Express)`, `Java (Spring Boot)`, `Go`
*   **Databases**: `MySQL`, `PostgreSQL`, `MongoDB`
*   **Infrastructure**: `Docker`, `Docker Compose`
*   **Web Server**: `Nginx`

---

### **Slide 5: 핵심 기능 및 취약점 시연 (Key Features & Demo)**

*   **1. 통합 대시보드**:
    *   직관적인 UI를 통해 원하는 취약점과 서버 언어를 선택하여 실습 가능
*   **2. 취약점 시연 (가장 중요한 부분)**:
    *   **시연 1: SQL Injection (SQL 주입)**
        *   **개념**: 악의적인 SQL 구문을 삽입하여 데이터베이스를 비정상적으로 조작하는 공격
        *   **시연**: 로그인 폼 등에서 SQL Injection을 시도하여 인증을 우회하는 과정 시연
        *   **코드 리뷰**: 공격이 성공하는 이유를 `servers/python-server/src/vulnerabilities/sql_injection.py` 와 같은 실제 코드를 통해 설명
    *   **시연 2: Cross-Site Scripting (XSS)**
        *   **개념**: 웹사이트에 악성 스크립트를 삽입하여 다른 사용자의 브라우저에서 실행되게 하는 공격
        *   **시연**: 게시판이나 검색창에 스크립트 구문을 입력하여 경고창(alert)이 뜨는 과정 시연
        *   **코드 리뷰**: 입력값 검증(Sanitization) 부재로 인해 XSS가 발생하는 부분을 `servers/php-server/src/Vulnerabilities/XSS/ReflectedXSS.php` 코드로 설명

---

### **Slide 6: 개발 및 테스트 프로세스 (Development & Testing)**

*   **간편한 개발 환경**: `Docker`를 통해 복잡한 설정 없이 `docker-compose up` 명령어 하나로 전체 환경 실행 가능
*   **빌드/실행 자동화**: `Makefile`을 이용하여 `make build`, `make logs` 등 주요 작업을 명령어 한 줄로 처리
*   **코드 품질 관리**: `tests/` 디렉토리의 테스트 코드를 통해 API 및 취약점 기능의 정상 동작을 검증

---

### **Slide 7: 향후 개선 계획 (Future Work)**

*   **취약점 확대**: `CSRF(Cross-Site Request Forgery)`, `NoSQL Injection`, `File Upload` 등 더 다양한 취약점 추가
*   **사용자 경험 개선**: 각 취약점에 대한 상세한 설명과 방어(Secure Coding) 예제 코드 제공
*   **CI/CD 도입**: `.github/workflows/simple-test.yml`를 확장하여 코드 변경 시 자동으로 테스트 및 빌드를 수행하는 파이프라인 구축

---

### **Slide 8: Q&A**

*   질의응답 시간을 가집니다.

---

### **Slide 9: 감사합니다**

*   마무리 인사를 전합니다.
