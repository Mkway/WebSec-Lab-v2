# 바로 시작할 수 있는 다음 단계

## 🚀 즉시 시작 가능한 작업 순서

### 1. XSS 모듈 구현 시작 (오늘 바로 시작)

#### Step 1: PHP XSS 모듈 생성 (30분)
```bash
# 폴더 구조 생성
mkdir -p servers/php-server/src/Vulnerabilities/XSS
mkdir -p servers/php-server/src/Controllers

# 파일 생성 순서
touch servers/php-server/src/Vulnerabilities/XSS/ReflectedXSS.php
touch servers/php-server/src/Vulnerabilities/XSS/StoredXSS.php
touch servers/php-server/src/Controllers/XSSController.php
```

#### Step 2: 기본 Reflected XSS 구현 (1시간)
- ReflectedXSS.php에 기본 취약점 코드 작성
- XSSController.php에 API 엔드포인트 추가
- 간단한 테스트로 동작 확인

#### Step 3: 페이로드 테스트 (30분)
- PayloadsAllTheThings의 XSS 페이로드 5-10개 선택
- 각 페이로드로 취약점 동작 확인
- 결과 로깅 시스템 추가

### 2. Node.js XSS 모듈 구현 (내일)

#### Step 1: Express 기본 구조 확인
```bash
# Node.js 서버 구조 확인
ls -la servers/nodejs-server/
cat servers/nodejs-server/package.json
```

#### Step 2: XSS 라우터 추가
- Express 라우터에 XSS 엔드포인트 추가
- Template injection 취약점 구현
- PHP와 동일한 API 구조 유지

### 3. 테스트 자동화 시스템 구축 (모레)

#### Step 1: 기본 테스트 러너 작성
```bash
mkdir -p tests/vulnerabilities
touch tests/vulnerabilities/XSSTest.php
touch tests/run_all_tests.php
```

#### Step 2: 언어간 비교 테스트
- 동일한 페이로드로 PHP와 Node.js 비교
- 결과 차이점 분석 및 로깅

## 🎯 우선순위별 구현 계획

### High Priority 🔴 (이번 주)
1. **PHP Reflected XSS** - 가장 기본적이고 중요
2. **Node.js Reflected XSS** - 언어간 비교를 위한 필수
3. **기본 테스트 시스템** - 품질 보장을 위한 필수

### Medium Priority 🟡 (다음 주)
1. **Stored XSS** - 데이터베이스 연동 필요
2. **DOM-based XSS** - 클라이언트 사이드 취약점
3. **Python XSS 모듈** - 세 번째 언어 지원

### Low Priority 🟢 (그 다음 주)
1. **Command Injection** - 새로운 취약점 유형
2. **통합 대시보드** - UI/UX 개선
3. **Java/Go XSS 모듈** - 추가 언어 지원

## 🛠️ 구체적인 첫 번째 작업

### 바로 지금 할 일: PHP Reflected XSS 구현

#### 1. ReflectedXSS.php 작성
```php
<?php
namespace WebSecLab\Vulnerabilities\XSS;

use WebSecLab\Vulnerabilities\VulnerabilityInterface;

class ReflectedXSS implements VulnerabilityInterface {
    public function executeVulnerable($payload, $params = []) {
        // 직접 출력 - 완전히 취약한 코드
        $userInput = $payload;
        return [
            'html_output' => "<div>사용자 입력: {$userInput}</div>",
            'vulnerability_detected' => $this->detectXSS($userInput),
            'execution_context' => 'vulnerable'
        ];
    }

    public function executeSafe($payload, $params = []) {
        // 완전히 안전한 코드
        $userInput = htmlspecialchars($payload, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        return [
            'html_output' => "<div>사용자 입력: {$userInput}</div>",
            'vulnerability_detected' => false,
            'execution_context' => 'safe'
        ];
    }

    private function detectXSS($input) {
        $xssPatterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/<iframe\b[^>]*>/i',
            '/javascript:/i',
            '/on\w+\s*=/i'
        ];

        foreach ($xssPatterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    public function getTestPayloads() {
        return [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '<iframe src="javascript:alert(\'XSS\')"></iframe>',
            '<body onload=alert("XSS")>',
            '<div style="background:url(javascript:alert(\'XSS\'))">',
            '"><script>alert("XSS")</script>'
        ];
    }
}
```

#### 2. XSSController.php 작성
```php
<?php
namespace WebSecLab\Controllers;

use WebSecLab\Vulnerabilities\XSS\ReflectedXSS;

class XSSController extends BaseController {
    private $reflectedXSS;

    public function __construct() {
        parent::__construct();
        $this->reflectedXSS = new ReflectedXSS();
    }

    public function reflected() {
        $payload = $this->getPayload();
        $mode = $this->getMode();

        try {
            if ($mode === 'vulnerable') {
                $result = $this->reflectedXSS->executeVulnerable($payload);
            } elseif ($mode === 'safe') {
                $result = $this->reflectedXSS->executeSafe($payload);
            } else {
                // 둘 다 실행해서 비교
                $result = [
                    'vulnerable' => $this->reflectedXSS->executeVulnerable($payload),
                    'safe' => $this->reflectedXSS->executeSafe($payload)
                ];
            }

            $this->sendSuccessResponse($result);
        } catch (Exception $e) {
            $this->sendErrorResponse($e->getMessage());
        }
    }

    public function getPayloads() {
        $payloads = $this->reflectedXSS->getTestPayloads();
        $this->sendSuccessResponse(['payloads' => $payloads]);
    }
}
```

#### 3. 라우터에 추가 (routes.php 또는 index.php)
```php
// XSS 엔드포인트 추가
$app->post('/vulnerabilities/xss/reflected', [XSSController::class, 'reflected']);
$app->get('/vulnerabilities/xss/payloads', [XSSController::class, 'getPayloads']);
```

## 🧪 즉시 테스트 방법

### cURL로 테스트
```bash
# 취약한 버전 테스트
curl -X POST http://localhost:8080/vulnerabilities/xss/reflected \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "<script>alert(\"XSS\")</script>",
    "mode": "vulnerable"
  }'

# 안전한 버전 테스트
curl -X POST http://localhost:8080/vulnerabilities/xss/reflected \
  -H "Content-Type: application/json" \
  -d '{
    "payload": "<script>alert(\"XSS\")</script>",
    "mode": "safe"
  }'

# 페이로드 목록 가져오기
curl http://localhost:8080/vulnerabilities/xss/payloads
```

## 📈 성과 측정

### 오늘 완료 목표
- [ ] PHP Reflected XSS 모듈 완성
- [ ] 기본 페이로드 5개 테스트 성공
- [ ] API 엔드포인트 정상 동작 확인

### 이번 주 완료 목표
- [ ] Node.js XSS 모듈 완성
- [ ] PHP와 Node.js 비교 테스트 성공
- [ ] 자동 테스트 스크립트 완성

### 다음 주 완료 목표
- [ ] Stored XSS 구현
- [ ] Python XSS 모듈 완성
- [ ] 통합 대시보드 프로토타입

---

**바로 시작하세요!** 첫 번째 PHP Reflected XSS 모듈부터 구현하면 나머지는 자연스럽게 따라올 것입니다.