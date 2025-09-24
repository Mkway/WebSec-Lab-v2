# Project File Structure

```
/home/wsl/WebSec-Lab-v2/
├───.env.example
├───.gitignore
├───CLAUDE.md
├───docker-compose.yml
├───Makefile
├───README.md
├───VULNERABILITY_PRIORITY.md
├───.claude/
│   └───settings.local.json
├───.git/...
├───.github/
│   └───workflows/
│       └───simple-test.yml
├───.playwright-mcp/
│   └───traces/
├───dashboard/
│   ├───Dockerfile
│   ├───nginx.conf
│   ├───assets/
│   │   ├───css/
│   │   │   └───dashboard.css
│   │   └───js/
│   │       ├───dashboard.js
│   │       ├───config/
│   │       │   └───servers.js
│   │       └───vulnerabilities/
│   │           ├───common.js
│   │           ├───sql-injection.js
│   │           └───xss.js
│   └───public/
│       ├───index.html
│       └───assets/
├───database/
│   ├───mongodb/
│   │   └───init/
│   │       └───01-init-mongodb.js
│   ├───mysql/
│   │   └───init/
│   └───postgres/
│       └───init/
├───docs/
│   ├───presentation-slides.md
│   ├───ui-improvement-plan.md
│   ├───ui-improvement-summary.md
│   ├───api/
│   │   └───api-reference.md
│   ├───architecture/
│   │   ├───project-structure.md
│   │   └───system-architecture.md
│   ├───deployment/
│   │   └───docker-setup.md
│   └───development/
│       └───development-guide.md
├───PayloadsAllTheThings/
├───plans/
├───scripts/
│   ├───smoke-test.sh
│   └───test-api.sh
├───servers/
│   ├───go-server/
│   │   ├───.env.example
│   │   ├───Dockerfile
│   │   ├───go.mod
│   │   ├───go.sum
│   │   └───src/
│   │       ├───main.go
│   │       └───sqlinjection/
│   │           └───sqlinjection.go
│   ├───java-server/
│   │   ├───.env.example
│   │   ├───Dockerfile
│   │   ├───pom.xml
│   │   ├───.mvn/
│   │   │   └───wrapper/...
│   │   └───src/
│   │       └───main/
│   │           ├───java/
│   │           │   └───com/
│   │           │       └───webseclab/
│   │           │           ├───SQLInjectionController.java
│   │           │           ├───SQLInjectionService.java
│   │           │           ├───WebSecLabApplication.java
│   │           │           └───XSSController.java
│   │           └───resources/
│   │               └───application.properties
│   ├───nodejs-server/
│   │   ├───.env.example
│   │   ├───Dockerfile
│   │   ├───package.json
│   │   ├───node_modules/...
│   │   └───src/
│   │       ├───app.js
│   │       ├───routes/
│   │       └───vulnerabilities/
│   │           └───NoSQLInjection.js
│   ├───php-server/
│   │   ├───.env.example
│   │   ├───apache.conf
│   │   ├───composer.json
│   │   ├───Dockerfile
│   │   ├───php.ini
│   │   ├───public/
│   │   │   ├───index.php
│   │   │   └───demo/
│   │   │       └───index.php
│   │   ├───src/
│   │   │   ├───Controllers/
│   │   │   │   ├───BaseController.php
│   │   │   │   ├───HealthController.php
│   │   │   │   ├───VulnerabilityController.php
│   │   │   │   └───XSSController.php
│   │   │   ├───Utils/
│   │   │   │   └───DatabaseManager.php
│   │   │   └───Vulnerabilities/
│   │   │       ├───SQLInjection.php
│   │   │       ├───VulnerabilityInterface.php
│   │   │       └───XSS/
│   │   │           ├───BaseXSS.php
│   │   │           ├───ReflectedXSS.php
│   │   │           └───XSSInterface.php
│   │   └───vendor/
│   │       ├───composer/...
│   │       ├───graham-campbell/...
│   │       ├───monolog/...
│   │       ├───phpoption/...
│   │       ├───predis/...
│   │       ├───psr/...
│   │       ├───symfony/...
│   │       └───vlucas/...
│   └───python-server/
│       ├───.env.example
│       ├───Dockerfile
│       ├───requirements.txt
│       └───src/
│           ├───app.py
│           └───vulnerabilities/
│               ├───__init__.py
│               ├───sql_injection.py
│               └───__pycache__/
└───tests/
    ├───api_test.php
    ├───XSSTest.php
    └───node_modules/...
```

# Important File Analysis

### 최상위 디렉토리 (`/`)

*   `docker-compose.yml`: **(매우 중요)** 이 프로젝트의 핵심 파일 중 하나입니다. `docker-compose`는 여러 개의 Docker 컨테이너(웹 서버, 데이터베이스 등)를 정의하고 실행하는 도구입니다. 이 파일을 통해 전체 애플리케이션의 구조와 각 서비스가 어떻게 연결되는지 파악할 수 있습니다.
*   `Makefile`: `make` 명령어를 사용하여 프로젝트의 빌드, 실행, 종료 등 반복적인 작업을 자동화하는 스크립트입니다. 예를 들어, `make build`나 `make up` 같은 명령어가 정의되어 있을 것입니다.
*   `README.md`: 프로젝트의 개요, 설치 방법, 사용법 등이 기술된 기본 문서입니다. 프로젝트를 처음 접할 때 가장 먼저 읽어야 할 파일입니다.
*   `.env.example`: 환경 변수 설정 예시 파일입니다. 각 서버에서 사용하는 데이터베이스 접속 정보, API 키 등의 설정값을 어떻게 구성해야 하는지 알려줍니다. 실제 운영 시에는 `.env` 파일을 만들어 사용합니다.

### `dashboard/` (대시보드 UI)

*   `nginx.conf`: 대시보드를 서비스하기 위한 Nginx 웹 서버의 설정 파일입니다. 특정 요청을 어떤 백엔드 서버로 전달할지 결정하는 리버스 프록시(Reverse Proxy) 역할 등을 수행합니다.
*   `public/index.html`: 대시보드 페이지의 메인 HTML 파일로, 웹 페이지의 전체적인 골격을 구성합니다.
*   `assets/js/dashboard.js`: 대시보드의 전반적인 UI 상호작용과 동적 기능을 담당하는 핵심 자바스크립트 파일입니다.
*   `assets/js/config/servers.js`: 대시보드가 통신해야 할 백엔드 서버들의 주소와 정보를 설정하는 파일입니다.
*   `assets/js/vulnerabilities/*.js`: 각 보안 취약점(XSS, SQL Injection 등)을 시연하고 테스트하기 위한 프론트엔드 로직이 담긴 자바스크립트 파일들입니다.

### `database/` (데이터베이스)

*   `mongodb/init/01-init-mongodb.js`, `mysql/init/*`, `postgres/init/*`: Docker 컨테이너가 처음 생성될 때 각 데이터베이스를 초기화하는 스크립트입니다. 주로 테이블 생성, 초기 데이터 삽입, 사용자 계정 설정 등의 작업을 수행합니다.

### `servers/` (백엔드 서버)

이 디렉토리는 각기 다른 프로그래밍 언어로 구현된 여러 백엔드 서버를 포함하고 있으며, 프로젝트의 핵심 로직을 담고 있습니다.

*   **`python-server/`**
    *   `src/app.py`: Python Flask/FastAPI 기반의 메인 애플리케이션 파일입니다. API 엔드포인트(라우팅) 정의와 서버 실행 로직이 포함됩니다.
    *   `src/vulnerabilities/sql_injection.py`: SQL Injection 취약점 관련 로직을 구현한 Python 코드입니다.
    *   `requirements.txt`: 이 Python 프로젝트에 필요한 라이브러리(의존성) 목록입니다.
    *   `Dockerfile`: `python-server`를 Docker 이미지로 빌드하기 위한 지침서입니다.

*   **`php-server/`**
    *   `public/index.php`: 모든 웹 요청이 처음으로 도달하는 진입점(Entry Point) 파일입니다.
    *   `src/Controllers/*.php`: HTTP 요청을 받아 처리하는 컨트롤러 클래스들입니다. `VulnerabilityController.php`가 취약점 관련 요청을 담당할 것으로 보입니다.
    *   `src/Vulnerabilities/*.php`: SQL Injection, XSS 등 각 취약점의 핵심 로직을 담고 있는 PHP 클래스 파일입니다.
    *   `composer.json`: PHP 프로젝트의 의존성을 관리하는 파일입니다.

*   **`nodejs-server/`, `go-server/`, `java-server/`**
    *   위 서버들도 각각의 언어와 프레임워크에 맞춰 유사한 구조를 가집니다. (예: `nodejs-server/src/app.js`, `java-server/src/main/java/.../WebSecLabApplication.java`, `go-server/src/main.go` 등이 각 서버의 메인 파일입니다.)

### `docs/` (문서)

*   `architecture/system-architecture.md`: 프로젝트의 전체 시스템 아키텍처를 설명하는 중요한 문서입니다.
*   `api/api-reference.md`: 백엔드 서버들이 제공하는 API의 명세서입니다.
*   `development/development-guide.md`: 개발 환경을 설정하고 프로젝트에 기여하는 방법을 안내하는 가이드입니다.

### `tests/` (테스트)

*   `api_test.php`, `XSSTest.php`: API와 XSS 취약점 등에 대한 테스트 코드를 담고 있습니다. 코드의 안정성과 기능의 정상 동작을 검증하는 역할을 합니다.