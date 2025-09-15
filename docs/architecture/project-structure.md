# 프로젝트 구조 가이드 📁

## 📋 전체 디렉토리 구조

```
websec-lab-v2/
├── 📄 README.md                           # 프로젝트 메인 문서
├── 🐳 docker-compose.yml                  # Docker 오케스트레이션
├── 🐳 docker-compose.dev.yml              # 개발 환경용
├── 🐳 docker-compose.prod.yml             # 프로덕션 환경용
├── ⚙️ .env.example                        # 환경 변수 템플릿
├── ⚙️ .env                                # 실제 환경 변수 (gitignore)
├── 🛠️ Makefile                           # 자동화 명령어
├── 📋 .gitignore                          # Git 제외 파일
├── 🔐 .dockerignore                       # Docker 제외 파일
│
├── 📚 docs/                               # 프로젝트 문서
│   ├── 🏗️ architecture/                   # 아키텍처 문서
│   │   ├── system-architecture.md         # 시스템 아키텍처
│   │   ├── project-structure.md           # 프로젝트 구조 (이 파일)
│   │   ├── database-design.md             # 데이터베이스 설계
│   │   └── security-considerations.md     # 보안 고려사항
│   ├── 🚀 deployment/                     # 배포 가이드
│   │   ├── docker-setup.md                # Docker 설정
│   │   ├── local-development.md           # 로컬 개발 환경
│   │   └── troubleshooting.md             # 문제 해결
│   ├── 🌐 api/                            # API 문서
│   │   ├── api-reference.md               # API 레퍼런스
│   │   ├── vulnerability-api.md           # 취약점 API
│   │   └── response-formats.md            # 응답 형식
│   └── 🔧 development/                    # 개발 가이드
│       ├── development-guide.md           # 개발 가이드
│       ├── adding-languages.md            # 새 언어 추가
│       ├── adding-vulnerabilities.md      # 새 취약점 추가
│       └── testing-guide.md               # 테스팅 가이드
│
├── 🎛️ dashboard/                          # 통합 대시보드 (PHP)
│   ├── 🐳 Dockerfile                      # Dashboard 컨테이너
│   ├── 📦 composer.json                   # PHP 의존성
│   ├── 📦 composer.lock
│   ├── 🌐 public/                         # 웹 루트
│   │   ├── 🏠 index.php                   # 메인 엔트리포인트
│   │   ├── 🎨 assets/                     # 정적 자원
│   │   │   ├── css/
│   │   │   │   ├── main.css               # 메인 스타일
│   │   │   │   ├── components.css         # 컴포넌트 스타일
│   │   │   │   └── themes.css             # 테마 스타일
│   │   │   ├── js/
│   │   │   │   ├── app.js                 # 메인 JavaScript
│   │   │   │   ├── vue-components.js      # Vue.js 컴포넌트
│   │   │   │   └── api-client.js          # API 클라이언트
│   │   │   └── images/
│   │   │       ├── logos/                 # 언어별 로고
│   │   │       └── icons/                 # 아이콘
│   │   └── 📁 uploads/                    # 업로드 파일 (임시)
│   ├── 💻 src/                            # PHP 소스코드
│   │   ├── 🎮 Controllers/                # 컨트롤러
│   │   │   ├── HomeController.php         # 홈 페이지
│   │   │   ├── LanguageTestController.php # 언어별 테스트
│   │   │   ├── ComparisonController.php   # 결과 비교
│   │   │   └── ApiController.php          # API 엔드포인트
│   │   ├── 🧩 Services/                   # 서비스 레이어
│   │   │   ├── MultiLanguageClient.php    # 멀티 언어 클라이언트
│   │   │   ├── TestResultAnalyzer.php     # 결과 분석기
│   │   │   ├── PayloadManager.php         # 페이로드 관리
│   │   │   └── ReportGenerator.php        # 리포트 생성
│   │   ├── 📊 Models/                     # 데이터 모델
│   │   │   ├── TestResult.php             # 테스트 결과
│   │   │   ├── VulnerabilityTest.php      # 취약점 테스트
│   │   │   ├── LanguageServer.php         # 언어 서버
│   │   │   └── User.php                   # 사용자 (선택적)
│   │   ├── 🎨 Views/                      # 뷰 템플릿
│   │   │   ├── layouts/                   # 레이아웃
│   │   │   │   ├── main.php               # 메인 레이아웃
│   │   │   │   └── api.php                # API 레이아웃
│   │   │   ├── components/                # 재사용 컴포넌트
│   │   │   │   ├── test-form.php          # 테스트 폼
│   │   │   │   ├── result-display.php     # 결과 표시
│   │   │   │   └── language-selector.php  # 언어 선택기
│   │   │   └── pages/                     # 페이지 템플릿
│   │   │       ├── home.php               # 홈 페이지
│   │   │       ├── cross-test.php         # 크로스 테스트
│   │   │       └── comparison.php         # 비교 결과
│   │   ├── ⚙️ Core/                       # 핵심 프레임워크
│   │   │   ├── Application.php            # 애플리케이션 클래스
│   │   │   ├── Router.php                 # 라우터
│   │   │   ├── Request.php                # HTTP 요청
│   │   │   ├── Response.php               # HTTP 응답
│   │   │   └── Container.php              # DI 컨테이너
│   │   └── 🔧 Utils/                      # 유틸리티
│   │       ├── HttpClient.php             # HTTP 클라이언트
│   │       ├── JsonValidator.php          # JSON 검증
│   │       └── Logger.php                 # 로거
│   ├── ⚙️ config/                         # 설정 파일
│   │   ├── app.php                        # 앱 설정
│   │   ├── database.php                   # DB 설정
│   │   └── servers.php                    # 언어 서버 설정
│   └── 🧪 tests/                          # 테스트
│       ├── Unit/                          # 단위 테스트
│       ├── Integration/                   # 통합 테스트
│       └── Feature/                       # 기능 테스트
│
├── 🖥️ servers/                           # 언어별 서버
│   ├── 🐘 php-server/                     # PHP 취약점 서버
│   │   ├── 🐳 Dockerfile
│   │   ├── 📦 composer.json
│   │   ├── 🌐 public/
│   │   │   ├── index.php                  # PHP 서버 엔트리포인트
│   │   │   └── .htaccess                  # Apache 설정
│   │   ├── 💻 src/
│   │   │   ├── Controllers/
│   │   │   │   ├── VulnerabilityController.php
│   │   │   │   └── HealthController.php
│   │   │   ├── Vulnerabilities/           # PHP 특화 취약점
│   │   │   │   ├── SQLInjection.php       # SQL 인젝션
│   │   │   │   ├── XSS.php                # XSS
│   │   │   │   ├── ObjectInjection.php    # 객체 인젝션
│   │   │   │   ├── FileInclusion.php      # LFI/RFI
│   │   │   │   ├── Deserialization.php    # 역직렬화
│   │   │   │   └── CodeInjection.php      # 코드 인젝션
│   │   │   ├── Models/
│   │   │   └── Utils/
│   │   ├── ⚙️ config/
│   │   └── 🧪 tests/
│   │
│   ├── 🟢 nodejs-server/                  # Node.js 취약점 서버
│   │   ├── 🐳 Dockerfile
│   │   ├── 📦 package.json
│   │   ├── 📦 package-lock.json
│   │   ├── 🖥️ server.js                   # Express 서버
│   │   ├── 📁 routes/
│   │   │   ├── vulnerabilities.js         # 취약점 라우트
│   │   │   ├── health.js                  # 헬스체크
│   │   │   └── index.js                   # 메인 라우트
│   │   ├── 🎮 controllers/
│   │   │   ├── vulnerabilityController.js
│   │   │   └── healthController.js
│   │   ├── 🛡️ vulnerabilities/            # Node.js 특화 취약점
│   │   │   ├── prototypePollution.js      # 프로토타입 오염
│   │   │   ├── commandInjection.js        # 명령어 인젝션
│   │   │   ├── nosqlInjection.js          # NoSQL 인젝션
│   │   │   ├── deserialization.js         # JSON 역직렬화
│   │   │   ├── regexDos.js                # RegEx DoS
│   │   │   └── packageVulns.js            # 패키지 취약점
│   │   ├── 📊 models/
│   │   ├── 🔧 utils/
│   │   ├── ⚙️ config/
│   │   └── 🧪 tests/
│   │
│   ├── 🐍 python-server/                  # Python Flask 서버
│   │   ├── 🐳 Dockerfile
│   │   ├── 📦 requirements.txt
│   │   ├── 🖥️ app.py                      # Flask 애플리케이션
│   │   ├── 🎮 controllers/
│   │   │   ├── vulnerability_controller.py
│   │   │   └── health_controller.py
│   │   ├── 🛡️ vulnerabilities/            # Python 특화 취약점
│   │   │   ├── ssti.py                    # SSTI
│   │   │   ├── pickle_deserialization.py  # Pickle 역직렬화
│   │   │   ├── sql_injection.py           # SQL 인젝션
│   │   │   ├── code_injection.py          # 코드 인젝션
│   │   │   ├── path_traversal.py          # 경로 순회
│   │   │   └── yaml_deserialization.py    # YAML 역직렬화
│   │   ├── 📊 models/
│   │   ├── 🔧 utils/
│   │   ├── ⚙️ config/
│   │   └── 🧪 tests/
│   │
│   ├── ☕ java-server/                    # Java Spring Boot 서버
│   │   ├── 🐳 Dockerfile
│   │   ├── 📦 pom.xml                     # Maven 설정
│   │   ├── 💻 src/main/java/com/webseclab/
│   │   │   ├── WebSecApplication.java     # Spring Boot 메인
│   │   │   ├── controllers/
│   │   │   │   ├── VulnerabilityController.java
│   │   │   │   └── HealthController.java
│   │   │   ├── vulnerabilities/           # Java 특화 취약점
│   │   │   │   ├── DeserializationController.java  # 역직렬화
│   │   │   │   ├── SQLInjectionController.java     # SQL 인젝션
│   │   │   │   ├── XXEController.java              # XXE
│   │   │   │   ├── XSSController.java              # XSS
│   │   │   │   └── SSRFController.java             # SSRF
│   │   │   ├── models/
│   │   │   ├── services/
│   │   │   └── utils/
│   │   ├── 📁 src/main/resources/
│   │   │   ├── application.properties      # Spring 설정
│   │   │   └── application-dev.properties  # 개발 설정
│   │   └── 🧪 src/test/java/
│   │
│   └── 🔵 go-server/                      # Go Gin 서버
│       ├── 🐳 Dockerfile
│       ├── 📦 go.mod                      # Go 모듈
│       ├── 📦 go.sum
│       ├── 🖥️ main.go                     # Go 메인
│       ├── 🎮 controllers/
│       │   ├── vulnerability_controller.go
│       │   └── health_controller.go
│       ├── 🛡️ vulnerabilities/            # Go 특화 취약점
│       │   ├── template_injection.go      # 템플릿 인젝션
│       │   ├── sql_injection.go           # SQL 인젝션
│       │   ├── command_injection.go       # 명령어 인젝션
│       │   ├── race_condition.go          # 레이스 컨디션
│       │   └── path_traversal.go          # 경로 순회
│       ├── 📊 models/
│       ├── 🔧 utils/
│       ├── ⚙️ config/
│       └── 🧪 tests/
│
├── 🗄️ databases/                         # 데이터베이스 설정
│   ├── 🐬 mysql/                          # MySQL 설정
│   │   ├── 🐳 Dockerfile                  # 커스텀 MySQL 이미지
│   │   ├── 📁 init/                       # 초기화 스크립트
│   │   │   ├── 01-create-database.sql     # 데이터베이스 생성
│   │   │   ├── 02-create-tables.sql       # 테이블 생성
│   │   │   └── 03-insert-sample-data.sql  # 샘플 데이터
│   │   └── 📁 config/
│   │       └── my.cnf                     # MySQL 설정
│   ├── 🐘 postgresql/                     # PostgreSQL 설정
│   │   ├── 🐳 Dockerfile
│   │   ├── 📁 init/
│   │   │   ├── 01-create-database.sql
│   │   │   ├── 02-create-tables.sql
│   │   │   └── 03-insert-sample-data.sql
│   │   └── 📁 config/
│   │       └── postgresql.conf
│   ├── 🍃 mongodb/                        # MongoDB 설정
│   │   ├── 🐳 Dockerfile
│   │   ├── 📁 init/
│   │   │   ├── 01-init-security-test.js   # 초기화 스크립트
│   │   │   └── 02-sample-data.js          # 샘플 데이터
│   │   └── 📁 config/
│   │       └── mongod.conf
│   └── 🔴 redis/                          # Redis 설정
│       ├── 🐳 Dockerfile
│       └── 📁 config/
│           └── redis.conf
│
├── 🌐 nginx/                              # Nginx 설정
│   ├── 🐳 Dockerfile
│   ├── 📁 sites-enabled/
│   │   ├── default.conf                   # 기본 사이트
│   │   └── api.conf                       # API 사이트
│   ├── 📁 ssl/                            # SSL 인증서
│   │   ├── nginx.crt                      # 자체 서명 인증서
│   │   └── nginx.key                      # 개인 키
│   └── 📁 conf.d/
│       ├── gzip.conf                      # 압축 설정
│       └── security.conf                  # 보안 헤더
│
├── 📁 shared/                             # 공유 리소스
│   ├── 🎯 payloads/                       # 취약점별 페이로드
│   │   ├── sql-injection/
│   │   │   ├── mysql.json                 # MySQL 전용
│   │   │   ├── postgresql.json            # PostgreSQL 전용
│   │   │   └── common.json                # 공통 페이로드
│   │   ├── xss/
│   │   │   ├── reflected.json             # 반사형 XSS
│   │   │   ├── stored.json                # 저장형 XSS
│   │   │   └── dom.json                   # DOM XSS
│   │   ├── deserialization/
│   │   │   ├── php.json                   # PHP 직렬화
│   │   │   ├── java.json                  # Java 직렬화
│   │   │   ├── python.json                # Python Pickle
│   │   │   └── nodejs.json                # Node.js JSON
│   │   └── command-injection/
│   │       ├── unix.json                  # Unix 명령어
│   │       ├── windows.json               # Windows 명령어
│   │       └── blind.json                 # 블라인드 인젝션
│   ├── ⚙️ configs/                        # 공통 설정
│   │   ├── vulnerability-types.json       # 취약점 타입 정의
│   │   ├── language-configs.json          # 언어별 설정
│   │   └── security-levels.json           # 보안 레벨 정의
│   └── 🧪 test-data/                      # 테스트 데이터
│       ├── sample-users.json              # 샘플 사용자
│       ├── test-scenarios.json            # 테스트 시나리오
│       └── expected-results.json          # 예상 결과
│
├── 🤖 scripts/                            # 자동화 스크립트
│   ├── 🚀 deploy.sh                       # 배포 스크립트
│   ├── 💾 backup.sh                       # 백업 스크립트
│   ├── 🔄 migrate.sh                      # 마이그레이션 스크립트
│   ├── 🧪 test.sh                         # 테스트 실행 스크립트
│   ├── 🧹 cleanup.sh                      # 정리 스크립트
│   └── 📊 health-check.sh                 # 헬스체크 스크립트
│
└── 📁 storage/                            # 임시 저장소
    ├── 📋 logs/                           # 로그 파일
    │   ├── dashboard.log                  # 대시보드 로그
    │   ├── php-server.log                 # PHP 서버 로그
    │   ├── nodejs-server.log              # Node.js 서버 로그
    │   └── error.log                      # 에러 로그
    ├── 💾 cache/                          # 캐시 파일
    ├── 📤 uploads/                        # 업로드 파일
    └── 📊 reports/                        # 생성된 리포트
        ├── test-results/                  # 테스트 결과
        └── analysis/                      # 분석 결과
```

## 🔧 주요 설정 파일

### 1. Docker Compose 설정
```yaml
# docker-compose.yml - 메인 설정
# docker-compose.dev.yml - 개발 환경 (볼륨 마운트, 핫 리로드)
# docker-compose.prod.yml - 프로덕션 환경 (최적화, 보안)
```

### 2. 환경 변수 (.env)
```bash
# 애플리케이션 설정
APP_ENV=development
APP_DEBUG=true
APP_URL=http://localhost

# 데이터베이스 설정
DB_MYSQL_HOST=mysql
DB_POSTGRES_HOST=postgres
DB_MONGODB_HOST=mongodb
DB_REDIS_HOST=redis

# 언어 서버 URL
PHP_SERVER_URL=http://php-server:8080
NODEJS_SERVER_URL=http://nodejs-server:3000
PYTHON_SERVER_URL=http://python-server:5000
JAVA_SERVER_URL=http://java-server:8081
GO_SERVER_URL=http://go-server:8082
```

### 3. Makefile 명령어
```makefile
# 주요 명령어들
make up          # 모든 서비스 시작
make down        # 모든 서비스 중지
make logs        # 로그 확인
make test        # 테스트 실행
make clean       # 정리
```

## 📝 파일 명명 규칙

### 1. 파일명
- **PHP**: PascalCase (UserController.php)
- **JavaScript**: camelCase (userController.js)
- **Python**: snake_case (user_controller.py)
- **Java**: PascalCase (UserController.java)
- **Go**: snake_case (user_controller.go)

### 2. 디렉토리명
- **일반**: kebab-case (user-management)
- **언어별**: language-server (php-server, nodejs-server)

### 3. 설정 파일
- **Docker**: Dockerfile, docker-compose.yml
- **환경**: .env, .env.example
- **설정**: config.php, application.properties

## 🎯 확장 가이드

### 새로운 언어 서버 추가
1. `servers/` 아래에 새 디렉토리 생성
2. Dockerfile 및 필요한 설정 파일 추가
3. 표준 API 인터페이스 구현
4. docker-compose.yml에 서비스 추가
5. Dashboard에 클라이언트 추가

### 새로운 취약점 추가
1. 각 언어 서버의 `vulnerabilities/` 디렉토리에 구현
2. `shared/payloads/`에 페이로드 추가
3. 표준 응답 형식 준수
4. 테스트 케이스 작성

이 구조는 확장성과 유지보수성을 위해 설계되었으며, 각 언어별 특성을 고려하면서도 일관된 패턴을 유지합니다.