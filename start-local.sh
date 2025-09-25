#!/bin/bash

echo "🛡️  WebSec-Lab v2 - 로컬 서버 시작"
echo "=================================="
echo ""

# 1. PHP 서버 시작 (포트 8080)
echo "🐘 PHP 서버 시작 중..."
cd /home/wsl/WebSec-Lab-v2/servers/php-server
php -S 0.0.0.0:8080 -t . &
PHP_PID=$!
echo "   ✅ PHP 서버: http://localhost:8080 (PID: $PHP_PID)"

# 2. Simple Dashboard 시작 (포트 80)
echo "🎨 Dashboard 시작 중..."
cd /home/wsl/WebSec-Lab-v2/dashboard-simple
sudo python3 -m http.server 80 &
DASHBOARD_PID=$!
echo "   ✅ Dashboard: http://localhost (PID: $DASHBOARD_PID)"

# 3. Node.js 서버 시작 (포트 3000) - 있다면
if [ -d "/home/wsl/WebSec-Lab-v2/servers/nodejs-server" ]; then
    echo "🟢 Node.js 서버 시작 중..."
    cd /home/wsl/WebSec-Lab-v2/servers/nodejs-server
    if [ -f "package.json" ] && [ -f "app.js" ]; then
        npm start &
        NODE_PID=$!
        echo "   ✅ Node.js 서버: http://localhost:3000 (PID: $NODE_PID)"
    else
        echo "   ⚠️ Node.js 서버 파일 없음"
    fi
fi

echo ""
echo "🎯 실행된 서비스:"
echo "   📊 대시보드:    http://localhost"
echo "   🐘 PHP 서버:    http://localhost:8080"
echo "   🟢 Node.js:     http://localhost:3000"
echo ""
echo "🛑 중지 방법:"
echo "   ./stop-local.sh"
echo ""

# PID 파일에 저장
echo $PHP_PID > /tmp/websec-php.pid
echo $DASHBOARD_PID > /tmp/websec-dashboard.pid
[ ! -z "$NODE_PID" ] && echo $NODE_PID > /tmp/websec-node.pid

echo "✅ 모든 서버가 시작되었습니다!"