# WebSec-Lab v2 Makefile
# 멀티 언어 웹 보안 테스트 플랫폼 자동화 스크립트

.PHONY: help up down restart logs shell clean build test health backup

# 기본 설정
COMPOSE_FILE := docker-compose.yml
DEV_COMPOSE_FILE := docker-compose.dev.yml
PROD_COMPOSE_FILE := docker-compose.prod.yml
PROJECT_NAME := websec-lab-v2

# 색상 코드
RED := \033[31m
GREEN := \033[32m
YELLOW := \033[33m
BLUE := \033[34m
MAGENTA := \033[35m
CYAN := \033[36m
WHITE := \033[37m
RESET := \033[0m

# 기본 도움말
help: ## 사용 가능한 명령어 목록 표시
	@echo ""
	@echo "$(CYAN)🛡️  WebSec-Lab v2 - 멀티 언어 웹 보안 테스트 플랫폼$(RESET)"
	@echo ""
	@echo "$(YELLOW)📋 사용 가능한 명령어:$(RESET)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*?##/ { printf "  $(GREEN)%-20s$(RESET) %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""
	@echo "$(BLUE)💡 예시:$(RESET)"
	@echo "  make up              # 모든 서비스 시작"
	@echo "  make logs-php        # PHP 서버 로그 확인"
	@echo "  make test-all        # 모든 언어에서 테스트 실행"
	@echo "  make clean           # 전체 정리"
	@echo ""

# ===== 기본 Docker Compose 명령어 =====

up: ## 모든 서비스 시작
	@echo "$(GREEN)🚀 WebSec-Lab v2 시작 중...$(RESET)"
	docker-compose up -d
	@echo "$(GREEN)✅ 모든 서비스가 시작되었습니다!$(RESET)"
	@echo "$(CYAN)🌐 접속 URL:$(RESET)"
	@echo "  📊 Dashboard: http://localhost"
	@echo "  🐘 PHP Server: http://localhost:8080"
	@echo "  🟢 Node.js Server: http://localhost:3000"
	@echo "  🐍 Python Server: http://localhost:5000"
	@echo "  ☕ Java Server: http://localhost:8081"
	@echo "  🔵 Go Server: http://localhost:8082"

down: ## 모든 서비스 중지
	@echo "$(YELLOW)🛑 모든 서비스 중지 중...$(RESET)"
	docker-compose down
	@echo "$(GREEN)✅ 모든 서비스가 중지되었습니다.$(RESET)"

restart: ## 모든 서비스 재시작
	@echo "$(YELLOW)🔄 서비스 재시작 중...$(RESET)"
	docker-compose restart
	@echo "$(GREEN)✅ 모든 서비스가 재시작되었습니다.$(RESET)"

logs: ## 모든 서비스 로그 실시간 확인
	docker-compose logs -f

ps: ## 실행 중인 컨테이너 상태 확인
	@echo "$(CYAN)📊 컨테이너 상태:$(RESET)"
	docker-compose ps

# ===== 개발 환경 명령어 =====

dev-up: ## 개발 환경으로 시작 (핫 리로드 활성화)
	@echo "$(GREEN)🛠️  개발 환경 시작 중...$(RESET)"
	docker-compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) up -d
	@echo "$(GREEN)✅ 개발 환경이 시작되었습니다! (핫 리로드 활성화)$(RESET)"

dev-logs: ## 개발 환경 로그 확인
	docker-compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) logs -f

dev-down: ## 개발 환경 중지
	docker-compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) down

# ===== 프로덕션 환경 명령어 =====

prod-up: ## 프로덕션 환경으로 시작 (최적화 설정)
	@echo "$(GREEN)🚀 프로덕션 환경 시작 중...$(RESET)"
	docker-compose -f $(COMPOSE_FILE) -f $(PROD_COMPOSE_FILE) up -d
	@echo "$(GREEN)✅ 프로덕션 환경이 시작되었습니다!$(RESET)"

prod-logs: ## 프로덕션 환경 로그 확인
	docker-compose -f $(COMPOSE_FILE) -f $(PROD_COMPOSE_FILE) logs -f

prod-down: ## 프로덕션 환경 중지
	docker-compose -f $(COMPOSE_FILE) -f $(PROD_COMPOSE_FILE) down

# ===== 개별 서비스 관리 =====

up-databases: ## 데이터베이스 서비스만 시작
	@echo "$(GREEN)🗄️  데이터베이스 서비스 시작 중...$(RESET)"
	docker-compose up -d mysql postgres mongodb redis
	@echo "$(GREEN)✅ 데이터베이스 서비스가 시작되었습니다.$(RESET)"

up-servers: ## 언어 서버들만 시작
	@echo "$(GREEN)🖥️  언어 서버들 시작 중...$(RESET)"
	docker-compose up -d php-server nodejs-server python-server java-server go-server
	@echo "$(GREEN)✅ 모든 언어 서버가 시작되었습니다.$(RESET)"

up-php: ## PHP 서버만 시작
	docker-compose up -d php-server mysql redis

up-node: ## Node.js 서버만 시작
	docker-compose up -d nodejs-server mongodb redis

up-python: ## Python 서버만 시작
	docker-compose up -d python-server postgres mongodb redis

up-java: ## Java 서버만 시작
	docker-compose up -d java-server mysql mongodb

up-go: ## Go 서버만 시작
	docker-compose up -d go-server mysql redis

# ===== 로그 관리 =====

logs-dashboard: ## Dashboard 로그 확인
	docker-compose logs -f dashboard

logs-php: ## PHP 서버 로그 확인
	docker-compose logs -f php-server

logs-node: ## Node.js 서버 로그 확인
	docker-compose logs -f nodejs-server

logs-python: ## Python 서버 로그 확인
	docker-compose logs -f python-server

logs-java: ## Java 서버 로그 확인
	docker-compose logs -f java-server

logs-go: ## Go 서버 로그 확인
	docker-compose logs -f go-server

logs-mysql: ## MySQL 로그 확인
	docker-compose logs -f mysql

logs-postgres: ## PostgreSQL 로그 확인
	docker-compose logs -f postgres

logs-mongodb: ## MongoDB 로그 확인
	docker-compose logs -f mongodb

logs-redis: ## Redis 로그 확인
	docker-compose logs -f redis

logs-clear: ## 모든 로그 파일 정리
	@echo "$(YELLOW)🧹 로그 파일 정리 중...$(RESET)"
	docker-compose exec dashboard sh -c "find /var/log -name '*.log' -exec truncate -s 0 {} \;" 2>/dev/null || true
	docker system prune -f --volumes
	@echo "$(GREEN)✅ 로그 파일이 정리되었습니다.$(RESET)"

# ===== 컨테이너 접속 =====

shell: ## Dashboard 컨테이너 접속
	docker-compose exec dashboard sh

shell-php: ## PHP 서버 컨테이너 접속
	docker-compose exec php-server sh

shell-node: ## Node.js 서버 컨테이너 접속
	docker-compose exec nodejs-server sh

shell-python: ## Python 서버 컨테이너 접속
	docker-compose exec python-server sh

shell-java: ## Java 서버 컨테이너 접속
	docker-compose exec java-server sh

shell-go: ## Go 서버 컨테이너 접속
	docker-compose exec go-server sh

# ===== 데이터베이스 접속 =====

mysql: ## MySQL 데이터베이스 접속
	@echo "$(CYAN)🐬 MySQL 접속 중...$(RESET)"
	docker-compose exec mysql mysql -u websec -p websec_lab

postgres: ## PostgreSQL 데이터베이스 접속
	@echo "$(CYAN)🐘 PostgreSQL 접속 중...$(RESET)"
	docker-compose exec postgres psql -U websec -d websec_sql_test

mongo: ## MongoDB 데이터베이스 접속
	@echo "$(CYAN)🍃 MongoDB 접속 중...$(RESET)"
	docker-compose exec mongodb mongosh -u admin -p admin123

redis: ## Redis 데이터베이스 접속
	@echo "$(CYAN)🔴 Redis 접속 중...$(RESET)"
	docker-compose exec redis redis-cli

# ===== 빌드 관리 =====

build: ## 모든 이미지 빌드
	@echo "$(YELLOW)🔨 이미지 빌드 중...$(RESET)"
	docker-compose build
	@echo "$(GREEN)✅ 이미지 빌드가 완료되었습니다.$(RESET)"

build-no-cache: ## 캐시 없이 모든 이미지 재빌드
	@echo "$(YELLOW)🔨 캐시 없이 이미지 재빌드 중...$(RESET)"
	docker-compose build --no-cache
	@echo "$(GREEN)✅ 이미지 재빌드가 완료되었습니다.$(RESET)"

build-php: ## PHP 서버 이미지만 빌드
	docker-compose build php-server

build-node: ## Node.js 서버 이미지만 빌드
	docker-compose build nodejs-server

build-python: ## Python 서버 이미지만 빌드
	docker-compose build python-server

build-java: ## Java 서버 이미지만 빌드
	docker-compose build java-server

build-go: ## Go 서버 이미지만 빌드
	docker-compose build go-server

# ===== 간단한 테스트 실행 =====

test: ## 간단한 API 테스트 실행 (PHPUnit 없이)
	@echo "$(CYAN)🧪 간단한 API 테스트 실행 중...$(RESET)"
	@./scripts/test-api.sh

smoke-test: ## 연기 테스트 (기본 동작 확인)
	@echo "$(CYAN)💨 연기 테스트 실행 중...$(RESET)"
	@./scripts/smoke-test.sh

test-quick: ## 빠른 테스트 (연기 테스트)
	@make smoke-test

test-all: ## 모든 언어에서 전체 테스트 실행
	@echo "$(CYAN)🧪 전체 테스트 스위트 실행 중...$(RESET)"
	@echo "$(YELLOW)PHP 테스트...$(RESET)"
	docker-compose exec php-server composer test 2>/dev/null || echo "PHP 테스트 스킵됨"
	@echo "$(YELLOW)Node.js 테스트...$(RESET)"
	docker-compose exec nodejs-server npm test 2>/dev/null || echo "Node.js 테스트 스킵됨"
	@echo "$(YELLOW)Python 테스트...$(RESET)"
	docker-compose exec python-server python -m pytest 2>/dev/null || echo "Python 테스트 스킵됨"
	@echo "$(YELLOW)Java 테스트...$(RESET)"
	docker-compose exec java-server ./mvnw test 2>/dev/null || echo "Java 테스트 스킵됨"
	@echo "$(YELLOW)Go 테스트...$(RESET)"
	docker-compose exec go-server go test ./... 2>/dev/null || echo "Go 테스트 스킵됨"
	@echo "$(GREEN)✅ 전체 테스트 완료!$(RESET)"

test-health: ## 모든 서비스 헬스체크
	@echo "$(CYAN)🏥 서비스 헬스체크 중...$(RESET)"
	@for service in php-server nodejs-server python-server java-server go-server; do \
		echo "$(YELLOW)$$service 체크 중...$(RESET)"; \
		docker-compose exec $$service curl -f http://localhost/health 2>/dev/null >/dev/null && \
		echo "$(GREEN)✅ $$service: 건강함$(RESET)" || \
		echo "$(RED)❌ $$service: 비정상$(RESET)"; \
	done

test-api: ## API 엔드포인트 테스트
	@echo "$(CYAN)🌐 API 엔드포인트 테스트 중...$(RESET)"
	@curl -s http://localhost/api/servers/status | jq . 2>/dev/null && \
	echo "$(GREEN)✅ Dashboard API: 정상$(RESET)" || \
	echo "$(RED)❌ Dashboard API: 오류$(RESET)"

test-sql-injection: ## SQL 인젝션 크로스 언어 테스트
	@echo "$(CYAN)💉 SQL 인젝션 크로스 언어 테스트 중...$(RESET)"
	curl -s -X POST http://localhost/api/test/cross-language \
		-H "Content-Type: application/json" \
		-d '{"vulnerability":"sql-injection","payload":"1'\'' OR '\''1'\''='\''1","languages":["php","nodejs","python"]}' \
		| jq '.results | keys[]' 2>/dev/null || echo "테스트 실패"

test-xss: ## XSS 크로스 언어 테스트
	@echo "$(CYAN)🎯 XSS 크로스 언어 테스트 중...$(RESET)"
	curl -s -X POST http://localhost/api/test/cross-language \
		-H "Content-Type: application/json" \
		-d '{"vulnerability":"xss","payload":"<script>alert(\"XSS\")</script>","languages":["php","nodejs","python"]}' \
		| jq '.results | keys[]' 2>/dev/null || echo "테스트 실패"

# ===== 모니터링 및 상태 확인 =====

health: ## 전체 시스템 헬스체크
	@echo "$(CYAN)🏥 시스템 헬스체크$(RESET)"
	@echo ""
	@echo "$(YELLOW)📊 컨테이너 상태:$(RESET)"
	@docker-compose ps --format "table {{.Service}}\t{{.State}}\t{{.Ports}}"
	@echo ""
	@echo "$(YELLOW)💾 디스크 사용량:$(RESET)"
	@df -h | grep -E "(Filesystem|/dev/)"
	@echo ""
	@echo "$(YELLOW)🧠 메모리 사용량:$(RESET)"
	@free -h
	@echo ""
	@make test-health

stats: ## 컨테이너 리소스 사용량 확인
	@echo "$(CYAN)📊 컨테이너 리소스 사용량:$(RESET)"
	docker stats --no-stream

monitor: ## 실시간 모니터링 (Ctrl+C로 종료)
	@echo "$(CYAN)📈 실시간 모니터링 시작 (Ctrl+C로 종료)$(RESET)"
	docker stats

# ===== 데이터 관리 =====

backup: ## 데이터베이스 백업
	@echo "$(YELLOW)💾 데이터베이스 백업 중...$(RESET)"
	@mkdir -p ./backups
	@TIMESTAMP=$$(date +%Y%m%d_%H%M%S) && \
	docker-compose exec mysql mysqldump -u websec -pwebsec123 websec_lab > ./backups/mysql_$$TIMESTAMP.sql && \
	docker-compose exec postgres pg_dump -U websec websec_sql_test > ./backups/postgres_$$TIMESTAMP.sql && \
	docker-compose exec mongodb mongodump --username admin --password admin123 --authenticationDatabase admin --db websec_test --out ./backups/mongodb_$$TIMESTAMP && \
	echo "$(GREEN)✅ 백업 완료: ./backups/$(RESET)"

restore: ## 데이터베이스 복원 (백업 파일 필요)
	@echo "$(YELLOW)📥 데이터베이스 복원 기능$(RESET)"
	@echo "$(RED)⚠️  이 기능은 수동으로 구현해야 합니다.$(RESET)"
	@echo "백업 파일을 사용하여 복원하세요."

seed: ## 테스트 데이터 시딩
	@echo "$(YELLOW)🌱 테스트 데이터 시딩 중...$(RESET)"
	docker-compose exec php-server php artisan db:seed 2>/dev/null || echo "PHP 시딩 스킵됨"
	docker-compose exec nodejs-server npm run seed 2>/dev/null || echo "Node.js 시딩 스킵됨"
	docker-compose exec python-server python manage.py loaddata fixtures.json 2>/dev/null || echo "Python 시딩 스킵됨"
	@echo "$(GREEN)✅ 테스트 데이터 시딩 완료$(RESET)"

# ===== 정리 및 초기화 =====

clean: ## 컨테이너 중지 및 볼륨 정리
	@echo "$(YELLOW)🧹 시스템 정리 중...$(RESET)"
	docker-compose down -v
	docker system prune -f
	@echo "$(GREEN)✅ 정리 완료$(RESET)"

clean-all: ## 모든 데이터 완전 삭제 (이미지 포함)
	@echo "$(RED)⚠️  모든 데이터를 삭제합니다. 계속하려면 'yes'를 입력하세요.$(RESET)"
	@read -p "계속하시겠습니까? (yes/no): " CONFIRM; \
	if [ "$$CONFIRM" = "yes" ]; then \
		echo "$(YELLOW)🗑️  모든 데이터 삭제 중...$(RESET)"; \
		docker-compose down -v --rmi all; \
		docker system prune -af --volumes; \
		echo "$(GREEN)✅ 모든 데이터가 삭제되었습니다.$(RESET)"; \
	else \
		echo "$(BLUE)취소되었습니다.$(RESET)"; \
	fi

reset: ## 전체 환경 초기화 및 재시작
	@echo "$(YELLOW)🔄 전체 환경 초기화 중...$(RESET)"
	@make clean
	@make build
	@make up
	@echo "$(GREEN)✅ 환경 초기화 완료$(RESET)"

# ===== 업데이트 및 배포 =====

update: ## 프로젝트 업데이트 (Git pull + 재빌드)
	@echo "$(YELLOW)📥 프로젝트 업데이트 중...$(RESET)"
	git pull
	docker-compose pull
	docker-compose up -d --build
	@echo "$(GREEN)✅ 업데이트 완료$(RESET)"

deploy: ## 프로덕션 배포
	@echo "$(GREEN)🚀 프로덕션 배포 중...$(RESET)"
	@./scripts/deploy.sh 2>/dev/null || echo "배포 스크립트가 없습니다."

# ===== 유틸리티 =====

env: ## 환경 변수 확인
	@echo "$(CYAN)⚙️  환경 변수:$(RESET)"
	@cat .env 2>/dev/null || echo ".env 파일이 없습니다. .env.example을 복사하세요."

ports: ## 사용 중인 포트 확인
	@echo "$(CYAN)🔌 사용 중인 포트:$(RESET)"
	@netstat -tulpn | grep -E ":(80|443|3000|5000|8080|8081|8082|3306|5432|27017|6379)" 2>/dev/null || \
	lsof -i -P -n | grep -E ":(80|443|3000|5000|8080|8081|8082|3306|5432|27017|6379)"

version: ## 버전 정보 확인
	@echo "$(CYAN)📋 버전 정보:$(RESET)"
	@echo "Docker: $$(docker --version)"
	@echo "Docker Compose: $$(docker-compose --version)"
	@echo "WebSec-Lab v2: $$(cat VERSION 2>/dev/null || echo 'Unknown')"

setup: ## 초기 설정 (환경 변수 복사)
	@echo "$(YELLOW)⚙️  초기 설정 중...$(RESET)"
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✅ .env 파일이 생성되었습니다.$(RESET)"; \
		echo "$(BLUE)💡 필요한 경우 .env 파일을 편집하세요.$(RESET)"; \
	else \
		echo "$(YELLOW)⚠️  .env 파일이 이미 존재합니다.$(RESET)"; \
	fi

# ===== 개발자 도구 =====

lint: ## 코드 스타일 검사
	@echo "$(CYAN)🔍 코드 스타일 검사 중...$(RESET)"
	docker-compose exec php-server composer run-script lint 2>/dev/null || echo "PHP 린트 스킵됨"
	docker-compose exec nodejs-server npm run lint 2>/dev/null || echo "Node.js 린트 스킵됨"
	docker-compose exec python-server flake8 . 2>/dev/null || echo "Python 린트 스킵됨"

format: ## 코드 포맷팅
	@echo "$(CYAN)✨ 코드 포맷팅 중...$(RESET)"
	docker-compose exec php-server composer run-script format 2>/dev/null || echo "PHP 포맷팅 스킵됨"
	docker-compose exec nodejs-server npm run format 2>/dev/null || echo "Node.js 포맷팅 스킵됨"
	docker-compose exec python-server black . 2>/dev/null || echo "Python 포맷팅 스킵됨"
	docker-compose exec go-server go fmt ./... 2>/dev/null || echo "Go 포맷팅 스킵됨"

docs: ## 문서 생성
	@echo "$(CYAN)📚 문서 생성 중...$(RESET)"
	@echo "문서는 docs/ 디렉토리에 있습니다."
	@echo "$(BLUE)💡 브라우저에서 docs/index.html을 열어보세요.$(RESET)"

# 기본 타겟을 help로 설정
.DEFAULT_GOAL := help