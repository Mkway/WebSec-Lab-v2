# Phase 2 구현 가이드

## 🎯 XSS 구현 상세 계획

### 1. PHP XSS 모듈 구조

#### 파일 구조
```
servers/php-server/src/
├── Vulnerabilities/
│   └── XSS/
│       ├── ReflectedXSS.php
│       ├── StoredXSS.php
│       ├── DOMBasedXSS.php
│       └── XSSBypassTechniques.php
├── Controllers/
│   └── XSSController.php
└── Utils/
    └── XSSPayloadProcessor.php
```

#### 구현 예시
```php
<?php
class ReflectedXSS implements VulnerabilityInterface {
    public function executeVulnerable($payload, $params) {
        // 직접 출력 - 취약한 코드
        return "Hello " . $_GET['name'];
    }

    public function executeSafe($payload, $params) {
        // 필터링된 출력 - 안전한 코드
        return "Hello " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
    }

    public function getTestPayloads() {
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')">',
        ];
    }
}
```

### 2. Command Injection 모듈 구조

#### 시나리오별 구현
```php
<?php
class CommandInjection implements VulnerabilityInterface {
    public function executePing($host) {
        // 취약한 구현
        $output = shell_exec("ping -c 1 " . $host);
        return $output;
    }

    public function executePingSafe($host) {
        // 안전한 구현
        $host = escapeshellarg($host);
        $output = shell_exec("ping -c 1 " . $host);
        return $output;
    }

    public function getTestPayloads() {
        return [
            '127.0.0.1; cat /etc/passwd',
            '127.0.0.1 && whoami',
            '127.0.0.1 | ls -la',
            '127.0.0.1$(cat /etc/passwd)',
            '127.0.0.1`id`',
        ];
    }
}
```

### 3. Node.js 구현 구조

#### Express 서버 구조
```javascript
// servers/nodejs-server/src/vulnerabilities/XSS.js
class XSSVulnerability {
    // Reflected XSS
    reflectedVulnerable(req, res) {
        const userInput = req.query.input;
        res.send(`<h1>Hello ${userInput}</h1>`);
    }

    reflectedSafe(req, res) {
        const userInput = req.query.input;
        const escaped = userInput.replace(/[<>&"']/g, function(match) {
            const escapeMap = {
                '<': '&lt;',
                '>': '&gt;',
                '&': '&amp;',
                '"': '&quot;',
                "'": '&#x27;'
            };
            return escapeMap[match];
        });
        res.send(`<h1>Hello ${escaped}</h1>`);
    }

    // Template Injection
    templateInjection(req, res) {
        const template = req.body.template;
        // Handlebars template injection
        const compiled = Handlebars.compile(template);
        res.send(compiled({}));
    }
}
```

### 4. Python Flask 구현

#### Flask 애플리케이션 구조
```python
# servers/python-server/src/vulnerabilities/xss.py
from flask import request, render_template_string
import html

class XSSVulnerability:
    def reflected_vulnerable(self):
        user_input = request.args.get('input', '')
        return f"<h1>Hello {user_input}</h1>"

    def reflected_safe(self):
        user_input = request.args.get('input', '')
        escaped = html.escape(user_input)
        return f"<h1>Hello {escaped}</h1>"

    def template_injection_vulnerable(self):
        template = request.form.get('template', '')
        # Jinja2 template injection
        return render_template_string(template)

    def ssti_payloads(self):
        return [
            "{{ 7*7 }}",
            "{{ config }}",
            "{{ ''.__class__.__mro__[1].__subclasses__() }}",
            "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}"
        ]
```

## 🧪 테스트 시스템 구축

### 1. 자동화된 테스트 스크립트

#### PHP 테스트 러너
```php
<?php
// tests/XSSTestRunner.php
class XSSTestRunner {
    private $testCases = [];
    private $results = [];

    public function __construct() {
        $this->loadTestCases();
    }

    public function runAllTests() {
        foreach ($this->testCases as $testCase) {
            $this->runTest($testCase);
        }
        return $this->generateReport();
    }

    private function runTest($testCase) {
        $startTime = microtime(true);

        try {
            $response = $this->sendRequest($testCase);
            $success = $this->validateResponse($response, $testCase);

            $this->results[] = [
                'test_name' => $testCase['name'],
                'payload' => $testCase['payload'],
                'expected' => $testCase['expected'],
                'actual' => $response,
                'success' => $success,
                'execution_time' => microtime(true) - $startTime
            ];
        } catch (Exception $e) {
            $this->results[] = [
                'test_name' => $testCase['name'],
                'error' => $e->getMessage(),
                'success' => false
            ];
        }
    }
}
```

### 2. 페이로드 관리 시스템

#### PayloadsAllTheThings 통합
```php
<?php
class PayloadManager {
    private $payloadsPath = './PayloadsAllTheThings/';

    public function getXSSPayloads() {
        $payloads = [];

        // Reflected XSS payloads
        $reflectedFile = $this->payloadsPath . 'XSS Injection/README.md';
        $payloads['reflected'] = $this->parsePayloadsFromFile($reflectedFile);

        // DOM XSS payloads
        $domFile = $this->payloadsPath . 'XSS Injection/DOM Based XSS.md';
        $payloads['dom'] = $this->parsePayloadsFromFile($domFile);

        return $payloads;
    }

    public function getCommandInjectionPayloads() {
        $cmdFile = $this->payloadsPath . 'Command Injection/README.md';
        return $this->parsePayloadsFromFile($cmdFile);
    }

    private function parsePayloadsFromFile($filePath) {
        if (!file_exists($filePath)) {
            return [];
        }

        $content = file_get_contents($filePath);
        // 마크다운에서 코드 블록 추출
        preg_match_all('/```(?:bash|javascript|html)?\n(.*?)\n```/s', $content, $matches);

        return array_filter($matches[1], function($payload) {
            return !empty(trim($payload));
        });
    }
}
```

## 🎨 통합 대시보드 설계

### 1. Frontend 구조 (Vue.js)

#### 컴포넌트 구조
```
frontend/
├── src/
│   ├── components/
│   │   ├── VulnerabilityTester.vue
│   │   ├── PayloadExplorer.vue
│   │   ├── ResultsAnalyzer.vue
│   │   └── LanguageComparator.vue
│   ├── views/
│   │   ├── Dashboard.vue
│   │   ├── XSSLab.vue
│   │   └── CommandInjectionLab.vue
│   └── services/
│       ├── ApiService.js
│       └── PayloadService.js
```

#### Vue 컴포넌트 예시
```vue
<!-- VulnerabilityTester.vue -->
<template>
  <div class="vulnerability-tester">
    <div class="language-selector">
      <button
        v-for="lang in languages"
        :key="lang"
        @click="selectLanguage(lang)"
        :class="{ active: selectedLanguage === lang }"
      >
        {{ lang.toUpperCase() }}
      </button>
    </div>

    <div class="payload-input">
      <textarea
        v-model="payload"
        placeholder="Enter your payload..."
        class="payload-textarea"
      ></textarea>
      <button @click="testPayload" class="test-button">
        Test Payload
      </button>
    </div>

    <div class="results" v-if="results">
      <div class="vulnerable-result">
        <h3>Vulnerable Code Result:</h3>
        <pre>{{ results.vulnerable }}</pre>
      </div>
      <div class="safe-result">
        <h3>Safe Code Result:</h3>
        <pre>{{ results.safe }}</pre>
      </div>
    </div>
  </div>
</template>

<script>
export default {
  name: 'VulnerabilityTester',
  data() {
    return {
      languages: ['php', 'nodejs', 'python', 'java', 'go'],
      selectedLanguage: 'php',
      payload: '',
      results: null
    }
  },
  methods: {
    async testPayload() {
      try {
        const response = await this.$http.post(`/api/${this.selectedLanguage}/xss`, {
          payload: this.payload,
          mode: 'both'
        });
        this.results = response.data;
      } catch (error) {
        console.error('Test failed:', error);
      }
    }
  }
}
</script>
```

### 2. API 게이트웨이 설계

#### 통합 API 엔드포인트
```php
<?php
// API Gateway for language comparison
class VulnerabilityGateway {
    private $servers = [
        'php' => 'http://localhost:8080',
        'nodejs' => 'http://localhost:3000',
        'python' => 'http://localhost:5000',
        'java' => 'http://localhost:8081',
        'go' => 'http://localhost:8082'
    ];

    public function testAllLanguages($vulnerability, $payload, $params = []) {
        $results = [];

        foreach ($this->servers as $language => $baseUrl) {
            try {
                $results[$language] = $this->testSingleLanguage(
                    $language,
                    $vulnerability,
                    $payload,
                    $params
                );
            } catch (Exception $e) {
                $results[$language] = [
                    'error' => $e->getMessage(),
                    'status' => 'failed'
                ];
            }
        }

        return $results;
    }

    private function testSingleLanguage($language, $vulnerability, $payload, $params) {
        $url = $this->servers[$language] . "/vulnerabilities/{$vulnerability}";

        $data = [
            'payload' => $payload,
            'mode' => 'both',
            'parameters' => $params
        ];

        $response = $this->sendRequest($url, $data);
        return json_decode($response, true);
    }
}
```

## 📊 모니터링 시스템

### 1. 실시간 로그 시스템
```php
<?php
class SecurityLogger {
    public function logAttackAttempt($vulnerability, $payload, $language, $success) {
        $logData = [
            'timestamp' => date('Y-m-d H:i:s'),
            'vulnerability_type' => $vulnerability,
            'payload' => $payload,
            'target_language' => $language,
            'attack_success' => $success,
            'ip_address' => $_SERVER['REMOTE_ADDR'],
            'user_agent' => $_SERVER['HTTP_USER_AGENT']
        ];

        // JSON 로그 저장
        $logFile = '/var/log/websec-lab/attacks.json';
        file_put_contents($logFile, json_encode($logData) . "\n", FILE_APPEND);

        // 실시간 알림 (WebSocket)
        $this->sendRealTimeNotification($logData);
    }
}
```

이 가이드를 기반으로 체계적이고 실전적인 Phase 2 개발을 진행할 수 있습니다.