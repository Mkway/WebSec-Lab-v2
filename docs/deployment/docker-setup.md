# Docker 구성 및 배포 가이드 🐳

## 📋 개요

WebSec-Lab v2는 Docker Compose를 사용하여 멀티 컨테이너 애플리케이션으로 구성됩니다. 각 언어별 서버와 데이터베이스들이 독립적인 컨테이너에서 실행되며, 하나의 통합된 네트워크에서 통신합니다.

## 🏗️ 컨테이너 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Host                              │
├─────────────────────────────────────────────────────────────┤
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐     │
│  │     Nginx     │ │   Dashboard   │ │  PHP Server   │     │
│  │   (Proxy)     │ │    (PHP)      │ │    (PHP)      │     │
│  │    :80/443    │ │               │ │     :8080     │     │
│  └───────────────┘ └───────────────┘ └───────────────┘     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐     │
│  │  Node.js      │ │    Python     │ │     Java      │     │
│  │   Server      │ │    Server     │ │    Server     │     │
│  │    :3000      │ │     :5000     │ │     :8081     │     │
│  └───────────────┘ └───────────────┘ └───────────────┘     │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────┐     │
│  │   Go Server   │ │     MySQL     │ │  PostgreSQL   │     │
│  │    :8082      │ │     :3306     │ │     :5432     │     │
│  └───────────────┘ └───────────────┘ └───────────────┘     │
│  ┌───────────────┐ ┌───────────────┐                       │
│  │   MongoDB     │ │     Redis     │                       │
│  │    :27017     │ │     :6379     │                       │
│  └───────────────┘ └───────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

## 📦 Docker Compose 설정

### 메인 구성 파일 (docker-compose.yml)

```yaml
version: '3.8'

services:
  # ===== Frontend & Proxy =====
  nginx:
    build: ./nginx
    container_name: websec-nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/sites-enabled:/etc/nginx/sites-enabled
      - ./nginx/ssl:/etc/nginx/ssl
      - ./dashboard/public:/var/www/html
    depends_on:
      - dashboard
    networks:
      - websec-network
    restart: unless-stopped

  dashboard:
    build: ./dashboard
    container_name: websec-dashboard
    volumes:
      - ./dashboard:/var/www/html
      - ./shared:/var/www/shared
    environment:
      - APP_ENV=production
      - DB_MYSQL_HOST=mysql
      - DB_POSTGRES_HOST=postgres
      - DB_MONGODB_HOST=mongodb
      - DB_REDIS_HOST=redis
      - PHP_SERVER_URL=http://php-server:8080
      - NODEJS_SERVER_URL=http://nodejs-server:3000
      - PYTHON_SERVER_URL=http://python-server:5000
      - JAVA_SERVER_URL=http://java-server:8081
      - GO_SERVER_URL=http://go-server:8082
    depends_on:
      - mysql
      - redis
    networks:
      - websec-network
    restart: unless-stopped

  # ===== Language Servers =====
  php-server:
    build: ./servers/php-server
    container_name: websec-php-server
    ports:
      - "8080:80"
    volumes:
      - ./servers/php-server:/var/www/html
      - ./shared:/var/www/shared
    environment:
      - APP_ENV=production
      - DB_MYSQL_HOST=mysql
      - DB_POSTGRES_HOST=postgres
      - DB_MONGODB_HOST=mongodb
      - DB_REDIS_HOST=redis
    depends_on:
      mysql:
        condition: service_healthy
      postgres:
        condition: service_healthy
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - websec-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  nodejs-server:
    build: ./servers/nodejs-server
    container_name: websec-nodejs-server
    ports:
      - "3000:3000"
    volumes:
      - ./servers/nodejs-server:/app
      - ./shared:/app/shared
    environment:
      - NODE_ENV=production
      - MONGODB_URL=mongodb://admin:admin123@mongodb:27017/websec_test?authSource=admin
      - REDIS_URL=redis://redis:6379
      - MYSQL_URL=mysql://websec:websec123@mysql:3306/websec_lab
    depends_on:
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - websec-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  python-server:
    build: ./servers/python-server
    container_name: websec-python-server
    ports:
      - "5000:5000"
    volumes:
      - ./servers/python-server:/app
      - ./shared:/app/shared
    environment:
      - FLASK_ENV=production
      - DATABASE_URL=postgresql://websec:websec123@postgres:5432/websec_sql_test
      - MONGODB_URL=mongodb://admin:admin123@mongodb:27017/websec_test?authSource=admin
      - REDIS_URL=redis://redis:6379
    depends_on:
      postgres:
        condition: service_healthy
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - websec-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  java-server:
    build: ./servers/java-server
    container_name: websec-java-server
    ports:
      - "8081:8080"
    volumes:
      - ./servers/java-server:/app
      - ./shared:/app/shared
    environment:
      - SPRING_PROFILES_ACTIVE=production
      - SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/websec_lab?useSSL=false&allowPublicKeyRetrieval=true
      - SPRING_DATASOURCE_USERNAME=websec
      - SPRING_DATASOURCE_PASSWORD=websec123
      - SPRING_DATA_MONGODB_URI=mongodb://admin:admin123@mongodb:27017/websec_test?authSource=admin
      - SPRING_REDIS_HOST=redis
      - SPRING_REDIS_PORT=6379
    depends_on:
      mysql:
        condition: service_healthy
      mongodb:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - websec-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M

  go-server:
    build: ./servers/go-server
    container_name: websec-go-server
    ports:
      - "8082:8080"
    volumes:
      - ./servers/go-server:/app
      - ./shared:/app/shared
    environment:
      - GIN_MODE=release
      - DB_MYSQL_HOST=mysql
      - DB_MYSQL_PORT=3306
      - DB_MYSQL_USER=websec
      - DB_MYSQL_PASSWORD=websec123
      - DB_MYSQL_NAME=websec_lab
      - REDIS_ADDR=redis:6379
      - MONGODB_URI=mongodb://admin:admin123@mongodb:27017/websec_test?authSource=admin
    depends_on:
      mysql:
        condition: service_healthy
      redis:
        condition: service_healthy
      mongodb:
        condition: service_healthy
    networks:
      - websec-network
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M

  # ===== Databases =====
  mysql:
    image: mysql:8.0
    container_name: websec-mysql
    environment:
      MYSQL_ROOT_PASSWORD: root123
      MYSQL_DATABASE: websec_lab
      MYSQL_USER: websec
      MYSQL_PASSWORD: websec123
    volumes:
      - mysql_data:/var/lib/mysql
      - ./databases/mysql/init:/docker-entrypoint-initdb.d
      - ./databases/mysql/config/my.cnf:/etc/mysql/conf.d/my.cnf
    ports:
      - "3306:3306"
    networks:
      - websec-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "websec", "-pwebsec123"]
      timeout: 20s
      retries: 10
      interval: 10s
    deploy:
      resources:
        limits:
          memory: 1G
        reservations:
          memory: 512M

  postgres:
    image: postgres:15
    container_name: websec-postgres
    environment:
      POSTGRES_DB: websec_sql_test
      POSTGRES_USER: websec
      POSTGRES_PASSWORD: websec123
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./databases/postgresql/init:/docker-entrypoint-initdb.d
      - ./databases/postgresql/config/postgresql.conf:/etc/postgresql/postgresql.conf
    ports:
      - "5432:5432"
    networks:
      - websec-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U websec -d websec_sql_test"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  mongodb:
    image: mongo:7
    container_name: websec-mongodb
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin
      MONGO_INITDB_ROOT_PASSWORD: admin123
      MONGO_INITDB_DATABASE: websec_test
    volumes:
      - mongodb_data:/data/db
      - ./databases/mongodb/init:/docker-entrypoint-initdb.d
      - ./databases/mongodb/config/mongod.conf:/etc/mongod.conf
    ports:
      - "27017:27017"
    networks:
      - websec-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "mongosh", "--eval", "db.adminCommand('ping')"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M

  redis:
    image: redis:7-alpine
    container_name: websec-redis
    volumes:
      - redis_data:/data
      - ./databases/redis/config/redis.conf:/usr/local/etc/redis/redis.conf
    ports:
      - "6379:6379"
    command: redis-server /usr/local/etc/redis/redis.conf
    networks:
      - websec-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
    deploy:
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M

# ===== Volumes =====
volumes:
  mysql_data:
    driver: local
  postgres_data:
    driver: local
  mongodb_data:
    driver: local
  redis_data:
    driver: local

# ===== Networks =====
networks:
  websec-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

### 개발 환경 설정 (docker-compose.dev.yml)

```yaml
version: '3.8'

services:
  dashboard:
    environment:
      - APP_ENV=development
      - APP_DEBUG=true
    volumes:
      - ./dashboard:/var/www/html:cached
      - ./shared:/var/www/shared:cached

  php-server:
    environment:
      - APP_ENV=development
      - APP_DEBUG=true
    volumes:
      - ./servers/php-server:/var/www/html:cached
      - ./shared:/var/www/shared:cached

  nodejs-server:
    environment:
      - NODE_ENV=development
    volumes:
      - ./servers/nodejs-server:/app:cached
      - ./shared:/app/shared:cached
    command: npm run dev

  python-server:
    environment:
      - FLASK_ENV=development
      - FLASK_DEBUG=true
    volumes:
      - ./servers/python-server:/app:cached
      - ./shared:/app/shared:cached
    command: flask run --host=0.0.0.0 --port=5000 --reload

  java-server:
    environment:
      - SPRING_PROFILES_ACTIVE=development
    volumes:
      - ./servers/java-server:/app:cached
      - ./shared:/app/shared:cached

  go-server:
    environment:
      - GIN_MODE=debug
    volumes:
      - ./servers/go-server:/app:cached
      - ./shared:/app/shared:cached
```

## 🛠️ Dockerfile 구성

### Dashboard (PHP) Dockerfile

```dockerfile
FROM php:8.2-fpm-alpine

# 시스템 패키지 설치
RUN apk add --no-cache \
    nginx \
    supervisor \
    curl \
    wget \
    git \
    unzip \
    libpng-dev \
    libzip-dev \
    freetype-dev \
    libjpeg-turbo-dev \
    libwebp-dev \
    oniguruma-dev

# PHP 확장 설치
RUN docker-php-ext-configure gd \
    --with-freetype \
    --with-jpeg \
    --with-webp

RUN docker-php-ext-install \
    pdo_mysql \
    pdo_pgsql \
    mysqli \
    gd \
    zip \
    mbstring \
    opcache

# Redis 확장 설치
RUN pecl install redis mongodb \
    && docker-php-ext-enable redis mongodb

# Composer 설치
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# 작업 디렉토리 설정
WORKDIR /var/www/html

# 설정 파일 복사
COPY nginx/default.conf /etc/nginx/http.d/default.conf
COPY supervisor/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY php/php.ini /usr/local/etc/php/php.ini

# 애플리케이션 파일 복사
COPY . .

# Composer 의존성 설치
RUN composer install --no-dev --optimize-autoloader

# 권한 설정
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# 포트 노출
EXPOSE 80

# 시작 명령
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
```

### Node.js Server Dockerfile

```dockerfile
FROM node:18-alpine

# 시스템 패키지 설치
RUN apk add --no-cache \
    curl \
    bash \
    git

# 작업 디렉토리 설정
WORKDIR /app

# package.json과 package-lock.json 복사
COPY package*.json ./

# 의존성 설치
RUN npm ci --only=production && npm cache clean --force

# 애플리케이션 코드 복사
COPY . .

# 비특권 사용자 생성
RUN addgroup -g 1001 -S nodejs \
    && adduser -S nodejs -u 1001

# 권한 설정
RUN chown -R nodejs:nodejs /app
USER nodejs

# 포트 노출
EXPOSE 3000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# 시작 명령
CMD ["node", "server.js"]
```

### Python Server Dockerfile

```dockerfile
FROM python:3.11-alpine

# 시스템 패키지 설치
RUN apk add --no-cache \
    gcc \
    musl-dev \
    postgresql-dev \
    curl \
    bash

# 작업 디렉토리 설정
WORKDIR /app

# requirements.txt 복사
COPY requirements.txt .

# Python 의존성 설치
RUN pip install --no-cache-dir -r requirements.txt

# 애플리케이션 코드 복사
COPY . .

# 비특권 사용자 생성
RUN adduser -D -s /bin/sh appuser
RUN chown -R appuser:appuser /app
USER appuser

# 포트 노출
EXPOSE 5000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# 시작 명령
CMD ["python", "app.py"]
```

## 🚀 배포 명령어

### 기본 배포

```bash
# 프로젝트 클론
git clone <repository-url>
cd websec-lab-v2

# 환경 변수 설정
cp .env.example .env
# .env 파일 편집

# 컨테이너 빌드 및 시작
docker-compose up -d

# 로그 확인
docker-compose logs -f

# 상태 확인
docker-compose ps
```

### 개발 환경 배포

```bash
# 개발 환경으로 시작
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# 핫 리로드 확인
docker-compose logs -f nodejs-server
```

### 프로덕션 환경 배포

```bash
# 프로덕션 환경으로 시작
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# 리소스 모니터링
docker stats
```

## 🔧 Makefile 자동화

```makefile
.PHONY: up down restart logs shell clean build test

# 환경 변수
COMPOSE_FILE := docker-compose.yml
DEV_COMPOSE_FILE := docker-compose.dev.yml
PROD_COMPOSE_FILE := docker-compose.prod.yml

# 기본 명령어
up:
	docker-compose up -d

down:
	docker-compose down

restart:
	docker-compose restart

logs:
	docker-compose logs -f

# 개발 환경
dev-up:
	docker-compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) up -d

dev-logs:
	docker-compose -f $(COMPOSE_FILE) -f $(DEV_COMPOSE_FILE) logs -f

# 프로덕션 환경
prod-up:
	docker-compose -f $(COMPOSE_FILE) -f $(PROD_COMPOSE_FILE) up -d

prod-logs:
	docker-compose -f $(COMPOSE_FILE) -f $(PROD_COMPOSE_FILE) logs -f

# 개별 서비스
up-databases:
	docker-compose up -d mysql postgres mongodb redis

up-servers:
	docker-compose up -d php-server nodejs-server python-server java-server go-server

# 빌드
build:
	docker-compose build

build-no-cache:
	docker-compose build --no-cache

# 컨테이너 접속
shell-dashboard:
	docker-compose exec dashboard sh

shell-php:
	docker-compose exec php-server sh

shell-node:
	docker-compose exec nodejs-server sh

shell-python:
	docker-compose exec python-server sh

# 데이터베이스 접속
mysql:
	docker-compose exec mysql mysql -u websec -p websec_lab

postgres:
	docker-compose exec postgres psql -U websec -d websec_sql_test

mongo:
	docker-compose exec mongodb mongosh -u admin -p admin123

redis:
	docker-compose exec redis redis-cli

# 테스트
test:
	@echo "Running tests across all servers..."
	docker-compose exec php-server composer test
	docker-compose exec nodejs-server npm test
	docker-compose exec python-server python -m pytest
	docker-compose exec java-server ./mvnw test
	docker-compose exec go-server go test ./...

# 헬스체크
health:
	@echo "Checking service health..."
	@for service in dashboard php-server nodejs-server python-server java-server go-server; do \
		echo "Checking $$service..."; \
		docker-compose exec $$service curl -f http://localhost/health || echo "$$service is unhealthy"; \
	done

# 정리
clean:
	docker-compose down -v
	docker system prune -f

clean-all:
	docker-compose down -v --rmi all
	docker system prune -af --volumes

# 백업
backup:
	./scripts/backup.sh

# 모니터링
stats:
	docker stats

ps:
	docker-compose ps

# 로그 파일 관리
logs-clear:
	docker-compose exec dashboard truncate -s 0 /var/log/*.log
	docker-compose logs --since 0m > /dev/null

# 업데이트
update:
	git pull
	docker-compose pull
	docker-compose up -d --build
```

## 📊 모니터링 및 헬스체크

### 헬스체크 구성

각 서비스는 자체 헬스체크를 포함합니다:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### 로그 관리

```bash
# 실시간 로그 확인
docker-compose logs -f [service-name]

# 특정 시간 이후 로그
docker-compose logs --since 2023-01-01T00:00:00Z

# 로그 크기 제한
docker-compose logs --tail 100

# 로그 파일로 저장
docker-compose logs > /var/log/websec-lab.log
```

## 🔒 보안 설정

### 네트워크 격리

```yaml
networks:
  websec-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
    driver_opts:
      com.docker.network.bridge.enable_icc: "true"
      com.docker.network.bridge.enable_ip_masquerade: "true"
```

### 리소스 제한

```yaml
deploy:
  resources:
    limits:
      cpus: '0.5'
      memory: 512M
    reservations:
      cpus: '0.25'
      memory: 256M
```

### 볼륨 권한

```bash
# 올바른 권한 설정
sudo chown -R 1000:1000 ./storage
sudo chmod -R 755 ./storage
```

이 Docker 구성은 안정적이고 확장 가능한 멀티 언어 웹 보안 테스트 환경을 제공합니다.