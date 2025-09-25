# WebSec-Lab v2 - 간단한 로컬 실행
# Docker Hub 문제 회피용

.PHONY: help start stop restart status test clean

# 기본 도움말
help:
	@echo "🛡️  WebSec-Lab v2 - 간단한 로컬 실행"
	@echo "=================================="
	@echo ""
	@echo "🎯 빠른 시작:"
	@echo "  make start       모든 서버 시작"
	@echo "  make stop        모든 서버 중지"
	@echo "  make restart     빠른 재시작"
	@echo ""
	@echo "🔧 관리:"
	@echo "  make status      서버 상태 확인"
	@echo "  make test        API 테스트"
	@echo "  make clean       완전 정리"
	@echo ""
	@echo "🌐 접속 URL:"
	@echo "  대시보드: http://localhost"
	@echo "  PHP:     http://localhost:8080"
	@echo "  Node.js: http://localhost:3000"

# 모든 서버 시작
start:
	@echo "🚀 WebSec-Lab v2 시작 중..."
	./start-local.sh

# 모든 서버 중지
stop:
	@echo "🛑 모든 서버 중지 중..."
	./stop-local.sh

# 빠른 재시작
restart:
	@echo "🔄 빠른 재시작 중..."
	make stop
	sleep 2
	make start

# 상태 확인
status:
	@echo "📊 서버 상태 확인:"
	@echo "📍 대시보드:"
	@curl -s -o /dev/null -w "  Status: %{http_code}\n" http://localhost/ || echo "  대시보드 오프라인"
	@echo "📍 PHP 서버:"
	@curl -s -o /dev/null -w "  Status: %{http_code}\n" http://localhost:8080/ || echo "  PHP 서버 오프라인"
	@echo "📍 Node.js 서버:"
	@curl -s -o /dev/null -w "  Status: %{http_code}\n" http://localhost:3000/ || echo "  Node.js 서버 오프라인"

# API 테스트
test:
	@echo "🧪 API 테스트:"
	@echo "💉 SQL Injection 테스트:"
	@curl -s -X POST http://localhost:8080/vulnerabilities/sql-injection \
		-H "Content-Type: application/json" \
		-d '{"mode":"vulnerable","username":"admin","password":"test"}' \
		| head -3 || echo "  SQL Injection API 오프라인"
	@echo ""
	@echo "🔥 XSS 테스트:"
	@curl -s -X POST http://localhost:8080/vulnerabilities/xss \
		-H "Content-Type: application/json" \
		-d '{"mode":"vulnerable","payload":"<script>alert(1)</script>"}' \
		| head -3 || echo "  XSS API 오프라인"

# 완전 정리
clean:
	@echo "🧹 완전 정리 중..."
	./stop-local.sh
	@echo "✅ 정리 완료!"