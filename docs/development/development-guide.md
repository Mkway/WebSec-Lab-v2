# 개발 가이드 🔧

## 📋 개요

WebSec-Lab v2는 모듈화된 구조로 설계되어 있어 새로운 언어나 취약점을 쉽게 추가할 수 있습니다. 이 가이드는 개발자가 프로젝트에 기여하는 방법을 설명합니다.

## 🛠️ 개발 환경 설정

### 1. 필수 요구사항

```bash
# 시스템 요구사항
- Docker 20.10+ & Docker Compose 2.0+
- Git 2.30+
- Make (선택사항)
- VS Code (권장 IDE)

# 시스템 리소스
- RAM: 최소 8GB (권장 16GB)
- Storage: 최소 10GB 여유 공간
- CPU: 최소 4코어 (권장 8코어)
```

### 2. 프로젝트 클론 및 설정

```bash
# 저장소 클론
git clone <repository-url>
cd websec-lab-v2

# 환경 변수 설정
cp .env.example .env

# 개발 환경 시작
make dev-up

# 또는
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

### 3. IDE 설정 (VS Code)

`.vscode/settings.json` 파일 생성:

```json
{
  "php.suggest.basic": true,
  "php.validate.executablePath": "/usr/bin/php",
  "javascript.preferences.includePackageJsonAutoImports": "on",
  "python.defaultInterpreterPath": "/usr/bin/python3",
  "java.home": "/usr/lib/jvm/java-17-openjdk",
  "go.gopath": "/go",
  "docker.defaultRegistryPath": "localhost:5000",
  "files.associations": {
    "*.php": "php",
    "*.js": "javascript",
    "*.py": "python",
    "*.java": "java",
    "*.go": "go",
    "docker-compose*.yml": "yaml",
    "Dockerfile*": "dockerfile"
  },
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.fixAll": true
  }
}
```

권장 VS Code 확장:

```json
{
  "recommendations": [
    "ms-vscode.vscode-docker",
    "bmewburn.vscode-intelephense-client",
    "ms-vscode.vscode-json",
    "ms-python.python",
    "Extension Pack for Java",
    "golang.go",
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode"
  ]
}
```

## 🏗️ 아키텍처 이해

### 1. 핵심 개념

```
┌─────────────────────────────────────────┐
│           Design Principles             │
├─────────────────────────────────────────┤
│ • Language Isolation                    │
│ • Standardized API Interface            │
│ • Plugin Architecture                   │
│ • Educational Focus                     │
│ • Container-First Design                │
└─────────────────────────────────────────┘
```

### 2. 표준 API 인터페이스

모든 언어 서버는 동일한 API 규격을 따라야 합니다:

```http
POST /vulnerabilities/{vulnerability-type}
Content-Type: application/json

{
  "payload": "test payload",
  "mode": "vulnerable|safe",
  "parameters": {}
}

Response:
{
  "language": "php|nodejs|python|java|go",
  "vulnerability": "vulnerability-type",
  "payload": "test payload",
  "mode": "vulnerable|safe",
  "result": {
    "success": true,
    "data": "...",
    "execution_time": 0.025
  },
  "analysis": {
    "risk_level": "low|medium|high|critical",
    "attack_type": "injection|bypass|escalation",
    "impact": "description"
  },
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 🆕 새로운 언어 서버 추가

### 1. 디렉토리 구조 생성

```bash
# 새 언어 서버 디렉토리 생성 (예: Ruby)
mkdir -p servers/ruby-server/{controllers,vulnerabilities,models,utils,config,tests}
mkdir -p servers/ruby-server/public

# Dockerfile 생성
touch servers/ruby-server/Dockerfile

# 의존성 파일 생성 (Ruby의 경우 Gemfile)
touch servers/ruby-server/Gemfile
```

### 2. Dockerfile 작성

```dockerfile
# servers/ruby-server/Dockerfile
FROM ruby:3.2-alpine

# 시스템 패키지 설치
RUN apk add --no-cache \
    build-base \
    postgresql-dev \
    curl \
    bash

# 작업 디렉토리 설정
WORKDIR /app

# Gemfile 복사 및 의존성 설치
COPY Gemfile Gemfile.lock ./
RUN bundle install

# 애플리케이션 코드 복사
COPY . .

# 비특권 사용자 생성
RUN adduser -D -s /bin/sh appuser
RUN chown -R appuser:appuser /app
USER appuser

# 포트 노출
EXPOSE 4567

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:4567/health || exit 1

# 시작 명령
CMD ["ruby", "app.rb"]
```

### 3. 메인 애플리케이션 파일

```ruby
# servers/ruby-server/app.rb
require 'sinatra'
require 'json'
require 'logger'

# 로거 설정
logger = Logger.new(STDOUT)
logger.level = Logger::INFO

# 미들웨어 설정
before do
  content_type :json
  logger.info "#{request.request_method} #{request.path_info}"
end

# 헬스체크 엔드포인트
get '/health' do
  {
    status: 'healthy',
    language: 'ruby',
    timestamp: Time.now.iso8601
  }.to_json
end

# 메인 정보 엔드포인트
get '/' do
  {
    language: 'Ruby',
    framework: 'Sinatra',
    version: RUBY_VERSION,
    vulnerabilities: [
      'code-injection',
      'yaml-deserialization',
      'erb-injection',
      'sql-injection'
    ]
  }.to_json
end

# 취약점 테스트 엔드포인트
post '/vulnerabilities/:type' do
  request_body = JSON.parse(request.body.read)
  payload = request_body['payload']
  mode = request_body['mode'] || 'vulnerable'
  
  # 취약점 타입별 처리
  case params[:type]
  when 'code-injection'
    require_relative 'vulnerabilities/code_injection'
    result = CodeInjection.test(payload, mode)
  when 'yaml-deserialization'
    require_relative 'vulnerabilities/yaml_deserialization'
    result = YamlDeserialization.test(payload, mode)
  # ... 기타 취약점들
  else
    halt 404, { error: 'Vulnerability type not found' }.to_json
  end
  
  # 표준 응답 형식
  {
    language: 'ruby',
    vulnerability: params[:type],
    payload: payload,
    mode: mode,
    result: result[:result],
    analysis: result[:analysis],
    timestamp: Time.now.iso8601
  }.to_json
end

# 서버 시작
set :bind, '0.0.0.0'
set :port, 4567
```

### 4. 취약점 모듈 구현

```ruby
# servers/ruby-server/vulnerabilities/code_injection.rb
require 'benchmark'

class CodeInjection
  def self.test(payload, mode)
    start_time = Time.now
    
    if mode == 'vulnerable'
      # 취약한 코드 실행
      begin
        # 🚨 위험: eval 사용
        result = eval(payload)
        
        {
          result: {
            success: true,
            data: result.to_s,
            execution_time: Time.now - start_time
          },
          analysis: {
            risk_level: 'critical',
            attack_type: 'code_injection',
            impact: 'Arbitrary Ruby code execution possible'
          }
        }
      rescue StandardError => e
        {
          result: {
            success: false,
            error: e.message,
            execution_time: Time.now - start_time
          },
          analysis: {
            risk_level: 'critical',
            attack_type: 'code_injection',
            impact: 'Code injection attempt blocked by error'
          }
        }
      end
    else
      # 안전한 코드 실행
      {
        result: {
          success: true,
          data: 'Safe mode: Input sanitized and not executed',
          execution_time: Time.now - start_time
        },
        analysis: {
          risk_level: 'low',
          attack_type: 'none',
          impact: 'No code execution - input safely handled'
        }
      }
    end
  end
end
```

### 5. Docker Compose에 추가

```yaml
# docker-compose.yml에 추가
ruby-server:
  build: ./servers/ruby-server
  container_name: websec-ruby-server
  ports:
    - "4567:4567"
  volumes:
    - ./servers/ruby-server:/app
    - ./shared:/app/shared
  environment:
    - RACK_ENV=production
    - DATABASE_URL=postgresql://websec:websec123@postgres:5432/websec_sql_test
    - REDIS_URL=redis://redis:6379
  depends_on:
    postgres:
      condition: service_healthy
    redis:
      condition: service_healthy
  networks:
    - websec-network
  restart: unless-stopped
```

### 6. Dashboard에 클라이언트 추가

```php
// dashboard/src/Services/MultiLanguageClient.php에 추가
private $servers = [
    'php' => 'http://php-server:8080',
    'nodejs' => 'http://nodejs-server:3000',
    'python' => 'http://python-server:5000',
    'java' => 'http://java-server:8081',
    'go' => 'http://go-server:8082',
    'ruby' => 'http://ruby-server:4567',  // 새로 추가
];

public function callRubyServer($vulnerability, $payload, $mode = 'vulnerable') {
    return $this->callLanguageServer('ruby', $vulnerability, $payload, $mode);
}
```

## 🛡️ 새로운 취약점 추가

### 1. 취약점 클래스 생성

각 언어별로 동일한 취약점을 구현:

#### PHP 구현
```php
<?php
// servers/php-server/src/Vulnerabilities/NewVulnerability.php

class NewVulnerability {
    public static function test($payload, $mode = 'vulnerable') {
        $start_time = microtime(true);
        
        if ($mode === 'vulnerable') {
            // 취약한 구현
            $result = self::executeVulnerableCode($payload);
        } else {
            // 안전한 구현
            $result = self::executeSafeCode($payload);
        }
        
        return [
            'result' => $result,
            'execution_time' => microtime(true) - $start_time,
            'analysis' => self::analyzeResult($result, $mode)
        ];
    }
    
    private static function executeVulnerableCode($payload) {
        // 취약한 코드 구현
    }
    
    private static function executeSafeCode($payload) {
        // 안전한 코드 구현
    }
    
    private static function analyzeResult($result, $mode) {
        return [
            'risk_level' => $mode === 'vulnerable' ? 'high' : 'low',
            'attack_type' => 'new_vulnerability_type',
            'impact' => 'Description of potential impact'
        ];
    }
}
```

#### Node.js 구현
```javascript
// servers/nodejs-server/vulnerabilities/newVulnerability.js

class NewVulnerability {
    static test(payload, mode = 'vulnerable') {
        const startTime = Date.now();
        
        if (mode === 'vulnerable') {
            // 취약한 구현
            const result = this.executeVulnerableCode(payload);
            return {
                result,
                execution_time: Date.now() - startTime,
                analysis: this.analyzeResult(result, mode)
            };
        } else {
            // 안전한 구현
            const result = this.executeSafeCode(payload);
            return {
                result,
                execution_time: Date.now() - startTime,
                analysis: this.analyzeResult(result, mode)
            };
        }
    }
    
    static executeVulnerableCode(payload) {
        // 취약한 코드 구현
    }
    
    static executeSafeCode(payload) {
        // 안전한 코드 구현
    }
    
    static analyzeResult(result, mode) {
        return {
            risk_level: mode === 'vulnerable' ? 'high' : 'low',
            attack_type: 'new_vulnerability_type',
            impact: 'Description of potential impact'
        };
    }
}

module.exports = NewVulnerability;
```

### 2. 페이로드 데이터 추가

```json
// shared/payloads/new-vulnerability.json
{
  "vulnerability_type": "new-vulnerability",
  "description": "Description of the new vulnerability",
  "payloads": {
    "basic": [
      "payload1",
      "payload2"
    ],
    "advanced": [
      "advanced_payload1",
      "advanced_payload2"
    ],
    "bypass": [
      "bypass_payload1",
      "bypass_payload2"
    ]
  },
  "language_specific": {
    "php": [
      "php_specific_payload1"
    ],
    "nodejs": [
      "nodejs_specific_payload1"
    ],
    "python": [
      "python_specific_payload1"
    ]
  }
}
```

### 3. 라우터에 엔드포인트 추가

각 언어별 라우터에 새로운 엔드포인트 추가:

```php
// PHP
$router->post('/vulnerabilities/new-vulnerability', 'VulnerabilityController@newVulnerability');
```

```javascript
// Node.js
router.post('/vulnerabilities/new-vulnerability', vulnerabilityController.newVulnerability);
```

## 🧪 테스트 작성

### 1. 단위 테스트

#### PHP (PHPUnit)
```php
<?php
// servers/php-server/tests/Unit/NewVulnerabilityTest.php

use PHPUnit\Framework\TestCase;

class NewVulnerabilityTest extends TestCase {
    public function testVulnerableMode() {
        $payload = "test_payload";
        $result = NewVulnerability::test($payload, 'vulnerable');
        
        $this->assertArrayHasKey('result', $result);
        $this->assertArrayHasKey('analysis', $result);
        $this->assertEquals('high', $result['analysis']['risk_level']);
    }
    
    public function testSafeMode() {
        $payload = "test_payload";
        $result = NewVulnerability::test($payload, 'safe');
        
        $this->assertEquals('low', $result['analysis']['risk_level']);
    }
}
```

#### Node.js (Jest)
```javascript
// servers/nodejs-server/tests/newVulnerability.test.js

const NewVulnerability = require('../vulnerabilities/newVulnerability');

describe('NewVulnerability', () => {
    test('should handle vulnerable mode', () => {
        const payload = 'test_payload';
        const result = NewVulnerability.test(payload, 'vulnerable');
        
        expect(result).toHaveProperty('result');
        expect(result).toHaveProperty('analysis');
        expect(result.analysis.risk_level).toBe('high');
    });
    
    test('should handle safe mode', () => {
        const payload = 'test_payload';
        const result = NewVulnerability.test(payload, 'safe');
        
        expect(result.analysis.risk_level).toBe('low');
    });
});
```

### 2. 통합 테스트

```bash
# 모든 언어에서 새로운 취약점 테스트
#!/bin/bash
# scripts/test-new-vulnerability.sh

echo "Testing new vulnerability across all languages..."

PAYLOAD="test_payload"
VULNERABILITY="new-vulnerability"

# 각 언어 서버 테스트
for lang in php nodejs python java go; do
    case $lang in
        php) PORT=8080 ;;
        nodejs) PORT=3000 ;;
        python) PORT=5000 ;;
        java) PORT=8081 ;;
        go) PORT=8082 ;;
    esac
    
    echo "Testing $lang server..."
    curl -s -X POST "http://localhost:$PORT/vulnerabilities/$VULNERABILITY" \
        -H "Content-Type: application/json" \
        -d "{\"payload\":\"$PAYLOAD\",\"mode\":\"vulnerable\"}" \
        | jq '.analysis.risk_level'
done
```

## 📝 코딩 표준

### 1. PHP 표준 (PSR-12)

```php
<?php

declare(strict_types=1);

namespace WebSecLab\Vulnerabilities;

class ExampleVulnerability
{
    private const RISK_LEVELS = ['low', 'medium', 'high', 'critical'];
    
    public function __construct(
        private string $payload,
        private string $mode = 'vulnerable'
    ) {
    }
    
    public function execute(): array
    {
        $startTime = microtime(true);
        
        try {
            $result = $this->mode === 'vulnerable'
                ? $this->executeVulnerableCode()
                : $this->executeSafeCode();
            
            return [
                'success' => true,
                'result' => $result,
                'execution_time' => microtime(true) - $startTime,
            ];
        } catch (Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
                'execution_time' => microtime(true) - $startTime,
            ];
        }
    }
}
```

### 2. JavaScript 표준 (Airbnb)

```javascript
// 클래스 기반 구조
class ExampleVulnerability {
  constructor(payload, mode = 'vulnerable') {
    this.payload = payload;
    this.mode = mode;
    this.riskLevels = ['low', 'medium', 'high', 'critical'];
  }

  async execute() {
    const startTime = Date.now();
    
    try {
      const result = this.mode === 'vulnerable'
        ? await this.executeVulnerableCode()
        : await this.executeSafeCode();
      
      return {
        success: true,
        result,
        execution_time: Date.now() - startTime,
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        execution_time: Date.now() - startTime,
      };
    }
  }

  async executeVulnerableCode() {
    // 구현
  }

  async executeSafeCode() {
    // 구현
  }
}

module.exports = ExampleVulnerability;
```

## 🔧 디버깅 가이드

### 1. 로그 확인

```bash
# 특정 서비스 로그
docker-compose logs -f php-server

# 실시간 로그 (모든 서비스)
docker-compose logs -f

# 오류 로그만 필터링
docker-compose logs | grep ERROR
```

### 2. 컨테이너 내부 접속

```bash
# PHP 서버 접속
docker-compose exec php-server sh

# Node.js 서버 접속
docker-compose exec nodejs-server sh

# 데이터베이스 접속
docker-compose exec mysql mysql -u websec -p
```

### 3. 개발 도구

#### PHP Xdebug 설정
```ini
; php.ini
[xdebug]
xdebug.mode=debug
xdebug.start_with_request=yes
xdebug.client_host=host.docker.internal
xdebug.client_port=9003
```

#### Node.js 디버깅
```bash
# 디버그 모드로 실행
docker-compose exec nodejs-server node --inspect=0.0.0.0:9229 server.js
```

## 📚 추가 리소스

### 1. 공식 문서
- [Docker Documentation](https://docs.docker.com/)
- [PHP PSR Standards](https://www.php-fig.org/psr/)
- [Node.js Best Practices](https://github.com/goldbergyoni/nodebestpractices)

### 2. 보안 리소스
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Common Weakness Enumeration](https://cwe.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### 3. 커뮤니티
- [WebSec-Lab Discussions](https://github.com/discussions)
- [Security Forums](https://security.stackexchange.com/)

이 가이드를 따라 개발하면 일관성 있고 확장 가능한 코드를 작성할 수 있습니다.