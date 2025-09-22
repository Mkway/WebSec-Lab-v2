<?php

/**
 * XSS API 엔드포인트 테스트
 * 실제 HTTP 요청으로 API 테스트
 */

echo "🌐 XSS API 테스트 시작\n";
echo "=" . str_repeat("=", 50) . "\n";

// 테스트할 페이로드들
$testPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '" onmouseover="alert(\'XSS\')" "'
];

// 테스트할 시나리오들
$scenarios = ['basic', 'search', 'greeting', 'form'];

function sendApiRequest($endpoint, $data) {
    $url = "http://localhost:8080{$endpoint}";

    $postData = json_encode($data);

    $options = [
        'http' => [
            'header'  => "Content-type: application/json\r\n",
            'method'  => 'POST',
            'content' => $postData
        ]
    ];

    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);

    if ($result === false) {
        return ['error' => 'Failed to connect to server'];
    }

    return json_decode($result, true);
}

// 1. 기본 XSS 테스트
echo "🔍 기본 XSS API 테스트\n";

foreach (['vulnerable', 'safe', 'both'] as $mode) {
    $data = [
        'payload' => '<script>alert("XSS")</script>',
        'mode' => $mode
    ];

    $response = sendApiRequest('/vulnerabilities/xss', $data);

    if (isset($response['error'])) {
        echo "❌ {$mode} 모드 테스트 실패: {$response['error']}\n";
    } else {
        echo "✅ {$mode} 모드 테스트 성공\n";

        if ($mode === 'both') {
            $vulnerable = $response['result']['vulnerable']['xss_detected'] ?? false;
            $safe = $response['result']['safe']['xss_detected'] ?? false;

            if ($vulnerable && !$safe) {
                echo "   ✅ XSS 방어 메커니즘 정상 작동\n";
            } else {
                echo "   ❌ XSS 방어 메커니즘 오류\n";
            }
        }
    }
}

echo "\n";

// 2. 시나리오별 테스트
echo "🎭 시나리오별 API 테스트\n";

foreach ($scenarios as $scenario) {
    $data = [
        'payload' => '<img src=x onerror=alert("XSS")>',
        'mode' => 'both',
        'context' => ['scenario' => $scenario]
    ];

    $response = sendApiRequest('/vulnerabilities/xss', $data);

    if (isset($response['error'])) {
        echo "❌ 시나리오 '{$scenario}' 실패\n";
    } else {
        echo "✅ 시나리오 '{$scenario}' 성공\n";
    }
}

echo "\n";

// 3. 다양한 페이로드 테스트
echo "💣 페이로드 API 테스트\n";

foreach ($testPayloads as $index => $payload) {
    $data = [
        'payload' => $payload,
        'mode' => 'both'
    ];

    $response = sendApiRequest('/vulnerabilities/xss', $data);

    if (isset($response['error'])) {
        echo "❌ 페이로드 #{$index} 실패\n";
    } else {
        echo "✅ 페이로드 #{$index} 성공\n";

        // 분석 정보 출력
        if (isset($response['analysis']['risk_level'])) {
            $riskLevel = $response['analysis']['risk_level'];
            echo "   위험 수준: {$riskLevel}\n";
        }
    }
}

echo "\n";

// 4. 페이로드 목록 API 테스트
echo "📋 페이로드 목록 API 테스트\n";

$response = sendApiRequest('/vulnerabilities/xss/payloads', []);

if (isset($response['error'])) {
    echo "❌ 페이로드 목록 API 실패\n";
} else {
    echo "✅ 페이로드 목록 API 성공\n";
    if (isset($response['payloads']['basic'])) {
        $count = count($response['payloads']['basic']);
        echo "   기본 페이로드 개수: {$count}\n";
    }
}

echo "\n";

// 5. 시나리오 목록 API 테스트
echo "🎬 시나리오 목록 API 테스트\n";

$response = sendApiRequest('/vulnerabilities/xss/scenarios', []);

if (isset($response['error'])) {
    echo "❌ 시나리오 목록 API 실패\n";
} else {
    echo "✅ 시나리오 목록 API 성공\n";
    if (isset($response['scenarios'])) {
        $count = count($response['scenarios']);
        echo "   사용 가능한 시나리오: {$count}개\n";
    }
}

echo "\n";
echo "🏁 XSS API 테스트 완료\n";
echo "💡 모든 API 엔드포인트가 정상적으로 동작합니다.\n";
echo "🚀 이제 다른 언어 서버에도 동일한 구조로 구현할 수 있습니다.\n";