# WebSec-Lab v2 - 통합 Makefile
# 프로파일 기반 Docker Compose 관리

.PHONY: help xss php nodejs python java go all clean logs test status

# 기본 도움말
help:
	@echo "🛡️  WebSec-Lab v2 - 통합 실행 가이드"
	@echo "===================================="
	@echo ""
	@echo "🎯 빠른 시작:"
	@echo "  make xss         XSS 테스트 (웹 UI + PHP + MySQL + Redis)"
	@echo "  make dashboard   웹 대시보드만"
	@echo "  make php         PHP 서버만"
	@echo "  make nodejs      Node.js 서버만"
	@echo "  make python      Python 서버만"
	@echo "  make java        Java 서버만"
	@echo "  make go          Go 서버만"
	@echo "  make all         모든 서버 + 데이터베이스"
	@echo ""
	@echo "🧪 테스트:"
	@echo "  make test-xss    XSS 테스트 실행"
	@echo "  make test-api    API 테스트 실행"
	@echo ""
	@echo "🔧 관리:"
	@echo "  make status      컨테이너 상태 확인"
	@echo "  make logs        실시간 로그 보기"
	@echo "  make stop        모든 컨테이너 중지"
	@echo "  make clean       완전 정리"
	@echo ""
	@echo "🌐 접속 URL:"
	@echo "  대시보드: http://localhost (웹 UI)"
	@echo "  PHP:     http://localhost:8080"
	@echo "  Node.js: http://localhost:3000"
	@echo "  Python:  http://localhost:5000"
	@echo "  Java:    http://localhost:8081"
	@echo "  Go:      http://localhost:8082"

# XSS 테스트 환경 (추천)
xss:
	@echo "🚀 XSS 테스트 환경 시작 중..."
	docker compose --profile core up -d --build
	@echo "✅ 완료! 웹 대시보드: http://localhost"
	@echo "✅ 완료! PHP 서버: http://localhost:8080"
	@echo "🧪 XSS 테스트: make test-xss"

# 웹 대시보드만
dashboard:
	@echo "🎨 웹 대시보드 시작 중..."
	docker compose --profile dashboard up -d --build dashboard php-server mysql redis
	@echo "✅ 완료! 웹 대시보드: http://localhost"

# 개별 언어 서버들
php:
	@echo "🚀 PHP 서버 시작 중..."
	docker compose --profile php up -d --build
	@echo "✅ 완료! http://localhost:8080"

nodejs:
	@echo "🚀 Node.js 서버 시작 중..."
	docker compose --profile nodejs up -d --build
	@echo "✅ 완료! http://localhost:3000"

python:
	@echo "🚀 Python 서버 시작 중..."
	docker compose --profile python up -d --build
	@echo "✅ 완료! http://localhost:5000"

java:
	@echo "🚀 Java 서버 시작 중..."
	docker compose --profile java up -d --build
	@echo "✅ 완료! http://localhost:8081"

go:
	@echo "🚀 Go 서버 시작 중..."
	docker compose --profile go up -d --build
	@echo "✅ 완료! http://localhost:8082"

# 모든 서비스
all:
	@echo "🚀 모든 서비스 시작 중..."
	docker compose --profile all up -d --build
	@echo "✅ 완료! 모든 서버가 실행됨"

# 테스트 실행
test-xss:
	@echo "🧪 XSS 테스트 프레임워크 실행 중..."
	php tests/XSSTest.php
	@echo ""

test-api:
	@echo "🌐 API 테스트 실행 중..."
	php tests/api_test.php

# 상태 및 관리
status:
	@echo "📊 현재 실행 중인 컨테이너:"
	@docker ps --filter "name=websec" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "실행 중인 컨테이너가 없습니다."

logs:
	@echo "📜 실시간 로그 (Ctrl+C로 종료)"
	docker compose logs -f

stop:
	@echo "🛑 모든 컨테이너 중지 중..."
	docker compose --profile all down
	@echo "✅ 모든 컨테이너가 중지됨"

clean:
	@echo "🧹 모든 컨테이너, 이미지, 볼륨 삭제 중..."
	docker compose --profile all down -v
	docker system prune -af --volumes
	@echo "✅ 모든 Docker 리소스가 정리됨"

# 개발용 명령어들
dev:
	@echo "🔧 개발 모드로 시작 (XSS 환경)"
	make xss
	@echo "📊 상태 확인:"
	make status

# 빠른 재시작
restart:
	@echo "🔄 빠른 재시작 중..."
	make stop
	make xss

# 백업 (중요한 데이터가 있을 경우)
backup:
	@echo "💾 데이터베이스 백업 중..."
	mkdir -p backups
	docker compose exec -T mysql mysqldump -u root -prootpass123 --all-databases > backups/mysql-backup-$(shell date +%Y%m%d_%H%M%S).sql
	@echo "✅ 백업 완료: backups/ 폴더 확인"