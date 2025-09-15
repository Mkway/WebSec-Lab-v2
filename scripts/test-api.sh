#!/bin/bash

# WebSec-Lab v2 API 간단 테스트 스크립트
# PHPUnit 없이 실제 API 동작만 빠르게 검증

set -e

echo "🧪 WebSec-Lab v2 API 테스트 시작..."
echo "=================================="

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 테스트 결과 카운터
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# 테스트 함수
test_endpoint() {
    local name="$1"
    local url="$2"
    local expected_status="$3"
    local check_content="$4"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Testing $name... "
    
    # HTTP 요청 및 응답 코드 확인
    response=$(curl -s -w "\n%{http_code}" "$url" 2>/dev/null || echo -e "\n000")
    http_code=$(echo "$response" | tail -n1)
    content=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" == "$expected_status" ]]; then
        if [[ -n "$check_content" && "$content" != *"$check_content"* ]]; then
            echo -e "${RED}FAIL${NC} (content mismatch)"
            FAILED_TESTS=$((FAILED_TESTS + 1))
            echo "  Expected: $check_content"
            echo "  Got: $content" | head -c 100
        else
            echo -e "${GREEN}PASS${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "${RED}FAIL${NC} (HTTP $http_code, expected $expected_status)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

# POST 요청 테스트 함수
test_post_endpoint() {
    local name="$1"
    local url="$2"
    local data="$3"
    local expected_status="$4"
    local check_content="$5"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -n "Testing $name... "
    
    response=$(curl -s -w "\n%{http_code}" -X POST -H "Content-Type: application/json" -d "$data" "$url" 2>/dev/null || echo -e "\n000")
    http_code=$(echo "$response" | tail -n1)
    content=$(echo "$response" | head -n -1)
    
    if [[ "$http_code" == "$expected_status" ]]; then
        if [[ -n "$check_content" && "$content" != *"$check_content"* ]]; then
            echo -e "${RED}FAIL${NC} (content mismatch)"
            FAILED_TESTS=$((FAILED_TESTS + 1))
        else
            echo -e "${GREEN}PASS${NC}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "${RED}FAIL${NC} (HTTP $http_code, expected $expected_status)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
}

echo -e "\n${BLUE}1. 기본 서버 상태 체크${NC}"
echo "------------------------"

# 기본 엔드포인트 테스트
test_endpoint "PHP Server Root" "http://localhost:8080/" "200" "WebSec-Lab PHP Server"
test_endpoint "PHP Health Check" "http://localhost:8080/health" "200" "healthy"
test_endpoint "PHP Vulnerabilities List" "http://localhost:8080/vulnerabilities" "200" "sql-injection"

echo -e "\n${BLUE}2. SQL Injection 모듈 테스트${NC}"
echo "----------------------------"

# SQL Injection 취약한 모드 테스트
test_post_endpoint "SQL Injection (Vulnerable)" \
    "http://localhost:8080/vulnerabilities/sql-injection" \
    '{"payload": "'\'' OR '\''1'\''='\''1", "mode": "vulnerable", "parameters": {"test_type": "login"}}' \
    "200" \
    "vulnerable_query"

# SQL Injection 안전한 모드 테스트
test_post_endpoint "SQL Injection (Safe)" \
    "http://localhost:8080/vulnerabilities/sql-injection" \
    '{"payload": "'\'' OR '\''1'\''='\''1", "mode": "safe", "parameters": {"test_type": "login"}}' \
    "200" \
    "safe_query"

# UNION 기반 SQL Injection 테스트
test_post_endpoint "SQL Injection (UNION)" \
    "http://localhost:8080/vulnerabilities/sql-injection" \
    '{"payload": "'\'' UNION SELECT 1,user(),version()--", "mode": "vulnerable", "parameters": {"test_type": "search"}}' \
    "200" \
    "UNION"

# Blind SQL Injection 테스트
test_post_endpoint "SQL Injection (Blind)" \
    "http://localhost:8080/vulnerabilities/sql-injection" \
    '{"payload": "1 AND 1=1", "mode": "vulnerable", "parameters": {"test_type": "blind"}}' \
    "200" \
    "boolean_result"

echo -e "\n${BLUE}3. 오류 처리 테스트${NC}"
echo "-------------------"

# 잘못된 취약점 타입
test_post_endpoint "Invalid Vulnerability Type" \
    "http://localhost:8080/vulnerabilities/invalid-type" \
    '{"payload": "test", "mode": "vulnerable"}' \
    "400" \
    "not supported"

# 잘못된 모드
test_post_endpoint "Invalid Mode" \
    "http://localhost:8080/vulnerabilities/sql-injection" \
    '{"payload": "test", "mode": "invalid"}' \
    "400" \
    "vulnerable.*safe"

echo -e "\n${BLUE}4. 성능 테스트 (응답 시간)${NC}"
echo "-------------------------"

echo -n "Response time test... "
start_time=$(date +%s.%N)
curl -s "http://localhost:8080/health" > /dev/null
end_time=$(date +%s.%N)
response_time=$(echo "$end_time - $start_time" | bc)

if (( $(echo "$response_time < 1.0" | bc -l) )); then
    echo -e "${GREEN}PASS${NC} (${response_time}s)"
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    echo -e "${YELLOW}SLOW${NC} (${response_time}s)"
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

echo -e "\n=================================="
echo -e "${BLUE}테스트 결과 요약${NC}"
echo "=================================="
echo "Total Tests: $TOTAL_TESTS"
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "\n${GREEN}🎉 모든 테스트 통과!${NC}"
    exit 0
else
    echo -e "\n${RED}❌ $FAILED_TESTS개 테스트 실패${NC}"
    exit 1
fi