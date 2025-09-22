<?php

require_once __DIR__ . '/../servers/php-server/vendor/autoload.php';

use WebSecLab\Vulnerabilities\XSS\ReflectedXSS;

/**
 * XSS 테스트 프레임워크
 * 모든 XSS 테스트의 기본 틀이 되는 테스트 클래스
 */
class XSSTest
{
    private ReflectedXSS $reflectedXSS;
    private array $testResults = [];
    private int $totalTests = 0;
    private int $passedTests = 0;
    private int $failedTests = 0;

    public function __construct()
    {
        $this->reflectedXSS = new ReflectedXSS();
        echo "🛡️  XSS 테스트 프레임워크 시작\n";
        echo "=" . str_repeat("=", 50) . "\n";
    }

    /**
     * 모든 XSS 테스트 실행
     */
    public function runAllTests(): void
    {
        echo "📋 XSS 테스트 실행 중...\n\n";

        // 1. 기본 XSS 테스트
        $this->testBasicXSS();

        // 2. 시나리오별 테스트
        $this->testScenarios();

        // 3. 페이로드 테스트
        $this->testPayloads();

        // 4. 방어 메커니즘 테스트
        $this->testDefenseMechanisms();

        // 5. 우회 기법 테스트
        $this->testBypassTechniques();

        // 결과 출력
        $this->printResults();
    }

    /**
     * 기본 XSS 기능 테스트
     */
    private function testBasicXSS(): void
    {
        echo "🔍 기본 XSS 테스트\n";

        // 취약한 버전 테스트
        $payload = '<script>alert("XSS")</script>';
        $vulnerableResult = $this->reflectedXSS->executeVulnerable($payload);

        $this->assert(
            $vulnerableResult['xss_detected'] === true,
            "취약한 코드에서 XSS 탐지",
            "XSS가 탐지되어야 함"
        );

        // 안전한 버전 테스트
        $safeResult = $this->reflectedXSS->executeSafe($payload);

        $this->assert(
            $safeResult['xss_detected'] === false,
            "안전한 코드에서 XSS 차단",
            "XSS가 차단되어야 함"
        );

        // HTML 출력 차이 확인
        $this->assert(
            $vulnerableResult['html_output'] !== $safeResult['html_output'],
            "취약한/안전한 코드 출력 차이",
            "출력 결과가 달라야 함"
        );

        echo "\n";
    }

    /**
     * 시나리오별 XSS 테스트
     */
    private function testScenarios(): void
    {
        echo "🎭 시나리오별 테스트\n";

        $scenarios = ['basic', 'search', 'greeting', 'form'];
        $payload = '<img src=x onerror=alert("XSS")>';

        foreach ($scenarios as $scenario) {
            $context = ['scenario' => $scenario];

            // 취약한 버전
            $vulnerableResult = $this->reflectedXSS->executeVulnerable($payload, $context);
            $this->assert(
                $vulnerableResult['xss_detected'] === true,
                "시나리오 '{$scenario}' - 취약한 버전",
                "XSS가 탐지되어야 함"
            );

            // 안전한 버전
            $safeResult = $this->reflectedXSS->executeSafe($payload, $context);
            $this->assert(
                $safeResult['xss_detected'] === false,
                "시나리오 '{$scenario}' - 안전한 버전",
                "XSS가 차단되어야 함"
            );
        }

        echo "\n";
    }

    /**
     * 다양한 페이로드 테스트
     */
    private function testPayloads(): void
    {
        echo "💣 페이로드 테스트\n";

        $payloads = $this->reflectedXSS->getTestPayloads();

        foreach ($payloads as $index => $payload) {
            // 취약한 버전에서는 탐지되어야 함
            $vulnerableResult = $this->reflectedXSS->executeVulnerable($payload);

            $isXSSPayload = $this->reflectedXSS->detectXSS($payload);

            if ($isXSSPayload) {
                $this->assert(
                    $vulnerableResult['xss_detected'] === true,
                    "페이로드 #{$index} 취약한 버전 탐지",
                    "XSS 페이로드가 탐지되어야 함"
                );

                // 안전한 버전에서는 차단되어야 함
                $safeResult = $this->reflectedXSS->executeSafe($payload);
                $this->assert(
                    $safeResult['xss_detected'] === false,
                    "페이로드 #{$index} 안전한 버전 차단",
                    "XSS 페이로드가 차단되어야 함"
                );
            }
        }

        echo "\n";
    }

    /**
     * 방어 메커니즘 테스트
     */
    private function testDefenseMechanisms(): void
    {
        echo "🛡️  방어 메커니즘 테스트\n";

        $maliciousPayloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            'javascript:alert("XSS")',
            '<svg onload=alert("XSS")>'
        ];

        foreach ($maliciousPayloads as $payload) {
            $safeResult = $this->reflectedXSS->executeSafe($payload);

            // HTML 이스케이프 확인
            $this->assert(
                strpos($safeResult['html_output'], '<script') === false,
                "Script 태그 이스케이프",
                "Script 태그가 이스케이프되어야 함"
            );

            $this->assert(
                !$safeResult['xss_detected'],
                "XSS 탐지 방지",
                "XSS가 탐지되지 않아야 함"
            );
        }

        echo "\n";
    }

    /**
     * 우회 기법 테스트
     */
    private function testBypassTechniques(): void
    {
        echo "🔓 우회 기법 테스트\n";

        $bypassPayloads = [
            // 대소문자 우회
            '<ScRiPt>alert("XSS")</ScRiPt>',
            // 속성 우회
            '" onmouseover="alert(\'XSS\')" "',
            // URL 인코딩 우회
            '%3Cscript%3Ealert("XSS")%3C/script%3E',
            // 이벤트 핸들러
            '<div onmouseover=alert("XSS")>test</div>'
        ];

        foreach ($bypassPayloads as $payload) {
            // 취약한 버전에서는 성공해야 함
            $vulnerableResult = $this->reflectedXSS->executeVulnerable($payload);

            if ($this->reflectedXSS->detectXSS($payload)) {
                $this->assert(
                    $vulnerableResult['xss_detected'] === true,
                    "우회 기법 성공 (취약한 버전)",
                    "우회 기법이 성공해야 함"
                );

                // 안전한 버전에서는 차단되어야 함
                $safeResult = $this->reflectedXSS->executeSafe($payload);
                $this->assert(
                    $safeResult['xss_detected'] === false,
                    "우회 기법 차단 (안전한 버전)",
                    "우회 기법이 차단되어야 함"
                );
            }
        }

        echo "\n";
    }

    /**
     * 테스트 어설션
     */
    private function assert(bool $condition, string $testName, string $description): void
    {
        $this->totalTests++;

        if ($condition) {
            $this->passedTests++;
            echo "✅ {$testName}\n";
            $this->testResults[] = [
                'name' => $testName,
                'status' => 'PASS',
                'description' => $description
            ];
        } else {
            $this->failedTests++;
            echo "❌ {$testName} - FAILED\n";
            echo "   기대: {$description}\n";
            $this->testResults[] = [
                'name' => $testName,
                'status' => 'FAIL',
                'description' => $description
            ];
        }
    }

    /**
     * 테스트 결과 출력
     */
    private function printResults(): void
    {
        echo "=" . str_repeat("=", 50) . "\n";
        echo "🏁 테스트 완료\n\n";

        echo "📊 테스트 결과:\n";
        echo "   총 테스트: {$this->totalTests}\n";
        echo "   성공: {$this->passedTests}\n";
        echo "   실패: {$this->failedTests}\n";

        $successRate = $this->totalTests > 0 ? ($this->passedTests / $this->totalTests) * 100 : 0;
        echo "   성공률: " . number_format($successRate, 1) . "%\n\n";

        if ($this->failedTests > 0) {
            echo "❌ 실패한 테스트:\n";
            foreach ($this->testResults as $result) {
                if ($result['status'] === 'FAIL') {
                    echo "   - {$result['name']}\n";
                }
            }
        } else {
            echo "🎉 모든 테스트가 성공했습니다!\n";
        }

        echo "\n💡 XSS 테스트 프레임워크가 모든 기능을 검증했습니다.\n";
        echo "   이제 다른 취약점 유형도 이 구조를 기반으로 구현할 수 있습니다.\n";
    }

    /**
     * 성능 테스트
     */
    public function runPerformanceTest(): void
    {
        echo "🚀 성능 테스트\n";

        $payload = '<script>alert("XSS")</script>';
        $iterations = 1000;

        $startTime = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $this->reflectedXSS->executeVulnerable($payload);
        }
        $vulnerableTime = microtime(true) - $startTime;

        $startTime = microtime(true);
        for ($i = 0; $i < $iterations; $i++) {
            $this->reflectedXSS->executeSafe($payload);
        }
        $safeTime = microtime(true) - $startTime;

        echo "💣 취약한 버전: " . number_format($vulnerableTime, 4) . "초 ({$iterations}회)\n";
        echo "🛡️  안전한 버전: " . number_format($safeTime, 4) . "초 ({$iterations}회)\n";
        echo "📈 성능 차이: " . number_format($safeTime - $vulnerableTime, 4) . "초\n\n";
    }
}

// 테스트 실행
if (basename(__FILE__) === basename($_SERVER['PHP_SELF'])) {
    $test = new XSSTest();
    $test->runAllTests();
    $test->runPerformanceTest();
}