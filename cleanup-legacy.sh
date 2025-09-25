#!/bin/bash

echo "🧹 WebSec-Lab v2 레거시 환경 정리 스크립트"
echo "============================================="
echo ""

# 현재 컨테이너 중지
echo "1. 기존 컨테이너 중지 중..."
docker compose down 2>/dev/null || echo "  기존 컨테이너가 없습니다"

# Vue 관련 파일들 백업
echo "2. Vue 환경 백업 중..."
mkdir -p backup-vue
cp -r dashboard/ backup-vue/ 2>/dev/null || echo "  dashboard 디렉토리가 없습니다"

# 기존 파일들을 백업으로 이동
echo "3. 기존 설정 파일 백업 중..."
mv docker-compose.yml docker-compose-old.yml 2>/dev/null || echo "  기존 docker-compose.yml 없음"
mv Makefile Makefile-old 2>/dev/null || echo "  기존 Makefile 없음"

# 새로운 파일들 활성화
echo "4. 새로운 설정 적용 중..."
mv docker-compose-new.yml docker-compose.yml
mv Makefile-new Makefile

echo ""
echo "✅ 레거시 정리 완료!"
echo ""
echo "📁 백업 파일:"
echo "  - backup-vue/dashboard/     (Vue.js 환경)"
echo "  - docker-compose-old.yml    (기존 Docker Compose)"
echo "  - Makefile-old              (기존 Makefile)"
echo ""
echo "🚀 새로운 환경 시작:"
echo "  make start"
echo ""