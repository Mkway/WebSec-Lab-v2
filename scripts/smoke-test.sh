#!/bin/bash

# WebSec-Lab v2 연기 테스트 (Smoke Test)
# 기본 기능이 동작하는지만 빠르게 확인

echo "💨 연기 테스트 시작..."

# 1. Docker 컨테이너 상태 확인
echo "🐳 Docker 컨테이너 상태 확인..."
if ! docker-compose ps | grep -q "Up"; then
    echo "❌ Docker 컨테이너가 실행되지 않음"
    exit 1
fi
echo "✅ Docker 컨테이너 실행 중"

# 2. 기본 포트 확인
echo "🔌 포트 연결 확인..."
ports=(8080 3000 5000 8081 8082 3306 5432 27017 6379)
for port in "${ports[@]}"; do
    if nc -z localhost $port 2>/dev/null; then
        echo "✅ Port $port: OK"
    else
        echo "❌ Port $port: 연결 실패"
    fi
done

# 3. 핵심 API 빠른 체크
echo "⚡ 핵심 API 빠른 체크..."

# PHP 서버 기본 응답
if curl -s http://localhost:8080/ | grep -q "PHP"; then
    echo "✅ PHP 서버: 응답 OK"
else
    echo "❌ PHP 서버: 응답 없음"
fi

# 헬스체크
if curl -s http://localhost:8080/health | grep -q "healthy"; then
    echo "✅ Health Check: OK"
else
    echo "❌ Health Check: 실패"
fi

# SQL Injection 모듈 기본 동작
if curl -s -X POST -H "Content-Type: application/json" \
   -d '{"payload": "test", "mode": "safe"}' \
   http://localhost:8080/vulnerabilities/sql-injection | grep -q "success"; then
    echo "✅ SQL Injection 모듈: 동작 OK"
else
    echo "❌ SQL Injection 모듈: 동작 실패"
fi

echo "💨 연기 테스트 완료!"