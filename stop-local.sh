#!/bin/bash

echo "🛑 WebSec-Lab v2 - 로컬 서버 중지"
echo "================================"
echo ""

# PID 파일에서 프로세스 중지
if [ -f /tmp/websec-dashboard.pid ]; then
    DASHBOARD_PID=$(cat /tmp/websec-dashboard.pid)
    sudo kill $DASHBOARD_PID 2>/dev/null && echo "   ✅ Dashboard 중지됨 (PID: $DASHBOARD_PID)"
    rm -f /tmp/websec-dashboard.pid
fi

if [ -f /tmp/websec-php.pid ]; then
    PHP_PID=$(cat /tmp/websec-php.pid)
    kill $PHP_PID 2>/dev/null && echo "   ✅ PHP 서버 중지됨 (PID: $PHP_PID)"
    rm -f /tmp/websec-php.pid
fi

if [ -f /tmp/websec-node.pid ]; then
    NODE_PID=$(cat /tmp/websec-node.pid)
    kill $NODE_PID 2>/dev/null && echo "   ✅ Node.js 서버 중지됨 (PID: $NODE_PID)"
    rm -f /tmp/websec-node.pid
fi

# 포트 정리 (혹시 남은 프로세스)
sudo lsof -ti:80 | xargs sudo kill -9 2>/dev/null || true
lsof -ti:8080 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true

echo "   🧹 포트 정리 완료"
echo ""
echo "✅ 모든 서버가 중지되었습니다!"