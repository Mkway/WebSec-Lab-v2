# 발표를 위한 파일 구조 설명 가이드

## 설명의 핵심이 되는 파일 구조 (PHP 서버 예시)

```
/home/wsl/WebSec-Lab-v2/
├───docker-compose.yml
├───dashboard/
│   ├───nginx.conf
│   └───public/
│       └───index.html
├───database/
│   └───mysql/
│       └───init/
└───servers/
    └───php-server/
        ├───public/
        │   └───index.php
        └───src/
            └───Vulnerabilities/
                └───SQLInjection.php
```

---

발표 시 아래 순서대로 파일 구조를 따라가며 설명하는 것을 추천합니다. 이 방법은 **사용자의 요청 흐름(Request Flow)**을 기반으로 하므로 청중이 프로젝트를 직관적으로 이해하는 데 도움이 됩니다.

### **1. "지휘 본부" - 모든 서비스의 설계도 (`docker-compose.yml`)**

*   **파일 위치**: `/docker-compose.yml`
*   **설명**: "가장 먼저 보여드릴 파일은 프로젝트의 전체 설계도인 `docker-compose.yml`입니다. 이 파일 하나에 저희 프로젝트를 구성하는 모든 서비스(대시보드, 5개의 다른 언어 서버, 3개의 데이터베이스)가 어떻게 정의되고 서로 어떻게 연결되는지가 모두 담겨 있습니다. 이것이 저희 프로젝트가 마이크로서비스 아키텍처를 따르고 있다는 가장 확실한 증거입니다."

### **2. "사용자의 첫 만남" - 대시보드 (`dashboard/`)**

*   **파일 위치**: `/dashboard/public/index.html`
*   **설명**: "사용자는 이 `index.html` 파일을 통해 저희 서비스를 처음 만나게 됩니다. 여기서 특정 취약점과 테스트할 서버를 선택합니다."
*   **파일 위치**: `/dashboard/nginx.conf`
*   **설명**: "사용자가 대시보드에서 'PHP 서버의 SQL Injection 테스트'를 누르면, 그 요청은 바로 이 `nginx.conf` 파일의 규칙에 따라 PHP 서버로 전달됩니다. Nginx가 '교통 경찰'처럼 사용자의 요청을 올바른 백엔드 서버로 안내하는 역할을 합니다."

### **3. "취약점의 핵심" - 백엔드 서버 (`servers/`)**

*   **파일 위치**: `/servers/php-server/` (하나의 예시로 PHP 서버를 선택)
*   **설명**: "이제 요청을 받은 PHP 서버로 가보겠습니다. 이 디렉토리는 PHP로 만들어진 독립적인 웹 서버입니다."
*   **파일 위치**: `/servers/php-server/public/index.php`
*   **설명**: "Nginx로부터 온 모든 요청은 이 `index.php` 파일이 가장 먼저 받습니다. 이 파일은 요청된 URL에 따라 어떤 컨트롤러를 실행할지 결정하는 '접수 창구' 역할을 합니다."
*   **파일 위치**: `/servers/php-server/src/Vulnerabilities/SQLInjection.php`
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

---
---

# `docker-compose.yml` 핵심 요약 (PPT용 - 수정본)

### **1. 서비스 정의 (Services)**

**Code:**
```yaml
services:
  dashboard:
    # ... 대시보드 서비스 설정 ...

  php-server:
    # ... PHP 서버 설정 ...

  nodejs-server:
    # ... Node.js 서버 설정 ...
  
  python-server:
    # ... Python 서버 설정 ...

  # ... (및 Java, Go 서버, 데이터베이스들) ...
```

**설명:**
"`services` 키 아래에 `dashboard`, `php-server`, `nodejs-server` 등 프로젝트를 구성하는 모든 독립적인 서비스(컨테이너)들을 정의하고 있습니다."

### **2. 대시보드 서비스 (Dashboard)**

**Code:**
```yaml
services:
  dashboard:
    build:
      context: ./dashboard
      dockerfile: Dockerfile
    ports:
      - "80:80"
    depends_on:
      - php-server
    profiles: ["core", "dashboard", "all"]
```

**설명:**
*   `build`: 미리 만들어진 `nginx` 이미지를 사용하는 대신, 우리 프로젝트의 `./dashboard` 폴더에 있는 `Dockerfile`을 사용해 직접 이미지를 빌드합니다.
*   `ports: - "80:80"`: 사용자가 웹 브라우저에서 `localhost` (80번 포트)로 접속하면 이 대시보드 서비스에 연결됩니다.
*   `depends_on`: 이 대시보드는 `php-server`가 실행된 후에 실행되도록 의존 관계를 설정합니다.
*   `profiles`: `docker-compose --profile dashboard up` 과 같은 명령어로 특정 서비스 그룹만 선택적으로 실행할 수 있게 해주는 기능입니다.

### **3. 백엔드 서버 (Backend Server - PHP 예시)**

**Code:**
```yaml
services:
  php-server:
    build:
      context: ./servers/php-server
    ports:
      - "8080:80"
    environment:
      - DB_HOST=mysql
      - DB_NAME=websec_php
    depends_on:
      - mysql
```

**설명:**
*   `build`: `./servers/php-server` 경로의 `Dockerfile`을 이용해 PHP 서버 이미지를 직접 만듭니다.
*   `ports: - "8080:80"`: 이 PHP 서버는 8080번 포트를 사용합니다.
*   `environment`: `DB_HOST` 환경 변수를 통해 이 서버가 `mysql` 서비스에 접속해야 함을 알려줍니다.
*   `depends_on`: `mysql` 서비스가 실행된 후에 실행되도록 의존 관계를 설정합니다.

### **4. 데이터베이스 서비스 (Database - MySQL 예시)**

**Code:**
```yaml
services:
  mysql:
    image: mysql:8.0
    ports:
      - "3307:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=rootpass123
    volumes:
      - ./database/mysql/init:/docker-entrypoint-initdb.d
```

**설명:**
*   `image: mysql:8.0`: MySQL 8.0 공식 이미지를 사용합니다.
*   `ports: - "3307:3306"`: 로컬 컴퓨터에 이미 MySQL이 설치되어 있을 경우를 대비해, 충돌을 피하고자 외부 포트를 3307로 설정하고, 컨테이너 내부의 3306 포트와 연결합니다.
*   `environment`: 데이터베이스의 루트 비밀번호 등을 설정합니다.
*   `volumes`: 컨테이너가 처음 생성될 때 `init` 폴더의 스크립트를 실행하여 데이터베이스와 테이블을 자동으로 생성합니다.

### **5. 네트워크 (Networks)**

**Code:**
```yaml
networks:
  websec-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

**설명:**
*   `websec-network`: 모든 서비스가 연결되는 `websec-network`라는 이름의 가상 네트워크를 정의합니다.
*   `ipam`: 이 내부 네트워크가 사용할 IP 주소 대역(`172.20.0.0/16`)을 직접 지정하여 네트워크 환경을 보다 체계적으로 관리합니다.
