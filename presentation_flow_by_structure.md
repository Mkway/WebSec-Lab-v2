# Presentation Flow by File Structure

## 프로젝트 파일 구조

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

---

## 발표를 위한 파일 구조 설명 가이드

발표 시 아래 순서대로 파일 구조를 따라가며 설명하는 것을 추천합니다. 이 방법은 **사용자의 요청 흐름(Request Flow)**을 기반으로 하므로 청중이 프로젝트를 직관적으로 이해하는 데 도움이 됩니다.

### **1. "지휘 본부" - 모든 서비스의 설계도 (`docker-compose.yml`)**

*   **파일 위치**: `/docker-compose.yml`
*   **설명**: "가장 먼저 보여드릴 파일은 프로젝트의 전체 설계도인 `docker-compose.yml`입니다. 이 파일 하나에 저희 프로젝트를 구성하는 모든 서비스(대시보드, 5개의 다른 언어 서버, 3개의 데이터베이스)가 어떻게 정의되고 서로 어떻게 연결되는지가 모두 담겨 있습니다. 이것이 저희 프로젝트가 마이크로서비스 아키텍처를 따르고 있다는 가장 확실한 증거입니다."

### **2. "사용자의 첫 만남" - 대시보드 (`dashboard/`)**

*   **파일 위치**: `/dashboard/public/index.html`
*   **설명**: "사용자는 이 `index.html` 파일을 통해 저희 서비스를 처음 만나게 됩니다. 여기서 특정 취약점과 테스트할 서버를 선택합니다."
*   **파일 위치**: `/dashboard/nginx.conf`
*   **설명**: "사용자가 대시보드에서 'Python 서버의 SQL Injection 테스트'를 누르면, 그 요청은 바로 이 `nginx.conf` 파일의 규칙에 따라 Python 서버로 전달됩니다. Nginx가 '교통 경찰'처럼 사용자의 요청을 올바른 백엔드 서버로 안내하는 역할을 합니다."

### **3. "취약점의 핵심" - 백엔드 서버 (`servers/`)**

*   **파일 위치**: `/servers/python-server/` (하나의 예시로 Python 서버를 선택)
*   **설명**: "이제 요청을 받은 Python 서버로 가보겠습니다. 이 디렉토리는 Python으로 만들어진 독립적인 웹 서버입니다."
*   **파일 위치**: `/servers/python-server/src/app.py`
*   **설명**: "Nginx로부터 온 요청은 이 `app.py` 파일이 가장 먼저 받습니다. 이 파일은 요청된 URL에 따라 어떤 함수를 실행할지 결정하는 '접수 창구' 역할을 합니다."
*   **파일 위치**: `/servers/python-server/src/vulnerabilities/sql_injection.py`
*   **설명**: "**바로 이 파일이 오늘 발표의 핵심입니다.** 여기서 SQL Injection 취약점이 실제로 어떻게 코딩되어 있는지 볼 수 있습니다. 사용자의 입력값을 아무런 검증 없이 그대로 SQL 쿼리에 넣어버리는 코드가 바로 여기에 있습니다. 이 코드로 인해 취약점이 발생하며, 저희는 이 환경을 통해 그 원리를 학습할 수 있습니다."

### **4. "데이터 저장소" - 데이터베이스 (`database/`)**

*   **파일 위치**: `/database/mysql/init/`
*   **설명**: "마지막으로, 취약한 백엔드 서버는 이 데이터베이스와 통신합니다. `database` 디렉토리 안에는 각 데이터베이스의 테이블과 초기 데이터를 정의하는 스크립트들이 들어있습니다."

### **요약 및 흐름 정리**

위 설명들을 바탕으로 전체 흐름을 다시 한번 요약하며 마무리합니다.

"정리하자면,
1.  사용자는 **`dashboard`**에서 공격을 시도하고,
2.  **`nginx`**가 요청을 올바른 **`servers`** 중 하나로 보냅니다.
3.  서버 안의 **`vulnerabilities`** 디렉토리에 있는 취약한 코드가 실행되어 **`database`**를 공격합니다.
4.  이 모든 서비스는 **`docker-compose.yml`** 파일 하나로 관리됩니다.

이렇게 파일 구조를 따라가면 저희 프로젝트가 어떻게 동작하는지 쉽게 이해하실 수 있습니다."
