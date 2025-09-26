# 🔧 WebSec-Lab v2 Swagger 기반 REST API 통일 계획

## 📋 프로젝트 개요
현재 각 언어별로 서로 다른 API 구조를 가진 서버들을 통합된 OpenAPI(Swagger) 명세서 기반의 표준화된 REST API로 마이그레이션하는 계획서입니다.

## 📊 현재 상태 분석

### 기존 API 패턴 분석
- **PHP (포트: 8080)**: 수동 라우팅, 혼합된 엔드포인트 구조
- **Node.js (포트: 3000)**: Express 기반, 일관된 JSON 응답
- **Python (포트: 5000)**: Flask 기반, 표준화된 구조
- **Java (포트: 8081)**: Spring Boot, 기본 구조만 존재
- **Go (포트: 8082)**: Gin 기반, 완전한 API 구현

### 공통 엔드포인트 패턴
```
GET  /health
GET  /
GET  /vulnerabilities
POST /vulnerabilities/{type}
GET  /xss/vulnerable
GET  /xss/safe
GET  /sql/vulnerable/login
GET  /sql/safe/login
```

## 🎯 통일된 Swagger API 설계

### 1. OpenAPI 3.0 명세서 구조
```yaml
openapi: 3.0.0
info:
  title: WebSec-Lab API
  version: 2.0.0
  description: Multi-language Web Security Testing Platform

servers:
  - url: http://localhost:8080 # PHP
  - url: http://localhost:3000 # Node.js
  - url: http://localhost:5000 # Python
  - url: http://localhost:8081 # Java
  - url: http://localhost:8082 # Go

paths:
  /health:
    get:
      summary: Health Check
      responses:
        '200':
          $ref: '#/components/responses/HealthResponse'

  /vulnerabilities/{type}:
    post:
      summary: Execute Vulnerability Test
      parameters:
        - name: type
          in: path
          required: true
          schema:
            enum: [sql-injection, xss, command-injection]
      requestBody:
        $ref: '#/components/requestBodies/VulnerabilityTest'
      responses:
        '200':
          $ref: '#/components/responses/VulnerabilityResult'
```

### 2. 표준 응답 구조
```json
{
  "success": true,
  "data": {
    "result": "실행 결과",
    "vulnerability_detected": true,
    "payload_used": "테스트 페이로드",
    "attack_success": true,
    "execution_time": "0.045s"
  },
  "metadata": {
    "language": "php",
    "vulnerability_type": "sql_injection",
    "mode": "vulnerable",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

## 🏗️ 구현 계획

### Phase 1: Swagger 문서 생성 (1-2일)
1. **통합 OpenAPI 명세서 작성** (`docs/api/swagger.yaml`)
2. **각 언어별 Swagger UI 통합**
3. **API 검증 도구 설정**

### Phase 2: 언어별 API 표준화 (3-5일)
1. **PHP**: 라우터 리팩토링, Swagger PHP 통합
2. **Node.js**: Express OpenAPI 미들웨어 추가
3. **Python**: Flask-RESTX 통합
4. **Java**: SpringDoc OpenAPI 통합
5. **Go**: Swaggo 통합

### Phase 3: 자동 문서화 및 테스트 (1-2주)
1. **API 문서 자동 생성**
2. **통합 테스트 스위트**
3. **Dashboard 연동**

## 🛠️ 언어별 구현 가이드

### 1. PHP 서버 (포트: 8080)
```php
// Swagger PHP 통합
/**
 * @OA\Info(title="WebSec-Lab PHP API", version="2.0.0")
 * @OA\Post(
 *     path="/vulnerabilities/{type}",
 *     @OA\Parameter(name="type", in="path", required=true),
 *     @OA\Response(response="200", description="Success")
 * )
 */

// 라우터 클래스 생성
class ApiRouter {
    private $routes = [];

    public function post($path, $handler) {
        $this->routes['POST'][$path] = $handler;
    }

    public function get($path, $handler) {
        $this->routes['GET'][$path] = $handler;
    }
}

// 표준 응답 포맷터
class ResponseFormatter {
    public static function success($data, $metadata) {
        return json_encode([
            'success' => true,
            'data' => $data,
            'metadata' => $metadata
        ]);
    }
}
```

#### 필요 패키지
```bash
composer require zircote/swagger-php
```

### 2. Node.js 서버 (포트: 3000)
```javascript
// express-openapi 통합
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'WebSec-Lab Node.js API',
      version: '2.0.0'
    }
  },
  apis: ['./src/routes/*.js']
};

const specs = swaggerJsdoc(swaggerOptions);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

// 표준 응답 미들웨어
const responseFormatter = (req, res, next) => {
  res.apiSuccess = (data, metadata) => {
    res.json({
      success: true,
      data,
      metadata: {
        ...metadata,
        language: 'nodejs',
        timestamp: new Date().toISOString()
      }
    });
  };
  next();
};
```

#### 필요 패키지
```bash
npm install swagger-ui-express swagger-jsdoc
```

### 3. Python 서버 (포트: 5000)
```python
# Flask-RESTX 통합
from flask_restx import Api, Resource, fields

api = Api(app, doc='/docs/', title='WebSec-Lab Python API', version='2.0.0')

# 모델 정의
vulnerability_model = api.model('VulnerabilityTest', {
    'mode': fields.String(required=True, enum=['vulnerable', 'safe']),
    'payload': fields.String(required=True)
})

response_model = api.model('ApiResponse', {
    'success': fields.Boolean,
    'data': fields.Raw,
    'metadata': fields.Raw
})

@api.route('/vulnerabilities/<string:vuln_type>')
class VulnerabilityAPI(Resource):
    @api.expect(vulnerability_model)
    @api.marshal_with(response_model)
    def post(self, vuln_type):
        # 구현
        pass
```

#### 필요 패키지
```bash
pip install flask-restx
```

### 4. Java 서버 (포트: 8081)
```java
// SpringDoc OpenAPI 통합
@OpenAPIDefinition(
    info = @Info(title = "WebSec-Lab Java API", version = "2.0.0")
)
@RestController
@RequestMapping("/api")
public class VulnerabilityController {

    @PostMapping("/vulnerabilities/{type}")
    @Operation(summary = "Execute vulnerability test")
    public ResponseEntity<ApiResponse> testVulnerability(
        @PathVariable String type,
        @RequestBody VulnerabilityRequest request) {

        return ResponseEntity.ok(
            ApiResponse.builder()
                .success(true)
                .data(result)
                .metadata(metadata)
                .build()
        );
    }
}

// 응답 DTO
@Data
@Builder
public class ApiResponse {
    private boolean success;
    private Object data;
    private Map<String, Object> metadata;
}
```

#### 필요 의존성 (pom.xml)
```xml
<dependency>
    <groupId>org.springdoc</groupId>
    <artifactId>springdoc-openapi-ui</artifactId>
    <version>1.7.0</version>
</dependency>
```

### 5. Go 서버 (포트: 8082)
```go
// Swaggo 통합
import (
    "github.com/swaggo/gin-swagger"
    "github.com/swaggo/files"
    _ "github.com/websec-lab/docs"
)

// @title WebSec-Lab Go API
// @version 2.0.0
// @host localhost:8082
func main() {
    r := gin.Default()
    r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

    // API 라우트
    api := r.Group("/api")
    api.POST("/vulnerabilities/:type", testVulnerability)
}

// @Summary Execute vulnerability test
// @Param type path string true "Vulnerability type"
// @Accept json
// @Produce json
// @Success 200 {object} ApiResponse
func testVulnerability(c *gin.Context) {
    // 구현
}

type ApiResponse struct {
    Success  bool                   `json:"success"`
    Data     interface{}           `json:"data"`
    Metadata map[string]interface{} `json:"metadata"`
}
```

#### 필요 패키지
```bash
go get github.com/swaggo/swag/cmd/swag
go get github.com/swaggo/gin-swagger
go get github.com/swaggo/files
```

## 🎨 Dashboard 통합 업데이트

### Vue.js 대시보드 개선 사항

#### 1. API 클라이언트 통일화
```javascript
// src/services/ApiClient.js
class ApiClient {
  constructor(baseURL, language) {
    this.baseURL = baseURL;
    this.language = language;
  }

  async testVulnerability(type, payload, mode = 'vulnerable') {
    const response = await fetch(`${this.baseURL}/vulnerabilities/${type}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload, mode })
    });
    return response.json();
  }

  async getSwaggerSpec() {
    return fetch(`${this.baseURL}/swagger.json`).then(r => r.json());
  }
}

// 언어별 클라이언트 인스턴스
export const apiClients = {
  php: new ApiClient('http://localhost:8080', 'php'),
  nodejs: new ApiClient('http://localhost:3000', 'nodejs'),
  python: new ApiClient('http://localhost:5000', 'python'),
  java: new ApiClient('http://localhost:8081', 'java'),
  go: new ApiClient('http://localhost:8082', 'go')
};
```

#### 2. 통합 Swagger 뷰어 추가
```vue
<!-- src/views/ApiDocs.vue -->
<template>
  <div class="api-docs">
    <h1>API Documentation</h1>
    <div class="server-tabs">
      <button v-for="server in servers"
              :key="server.name"
              :class="{ active: currentServer === server.name }"
              @click="selectServer(server)">
        {{ server.name }} ({{ server.port }})
      </button>
    </div>
    <div class="swagger-container">
      <iframe :src="swaggerUrl" frameborder="0"></iframe>
    </div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      currentServer: 'php',
      servers: [
        { name: 'php', port: 8080 },
        { name: 'nodejs', port: 3000 },
        { name: 'python', port: 5000 },
        { name: 'java', port: 8081 },
        { name: 'go', port: 8082 }
      ]
    };
  },
  computed: {
    swaggerUrl() {
      const server = this.servers.find(s => s.name === this.currentServer);
      return `http://localhost:${server.port}/swagger-ui/`;
    }
  },
  methods: {
    selectServer(server) {
      this.currentServer = server.name;
    }
  }
};
</script>
```

#### 3. Vue Router 업데이트
```javascript
// src/router/index.js
const routes = [
  // 기존 라우트들...
  {
    path: '/api-docs',
    name: 'ApiDocs',
    component: () => import('../views/ApiDocs.vue')
  }
];
```

## 🚀 구현 우선순위

### 즉시 구현 (1-2일)
1. ✅ **통합 OpenAPI 명세서 작성** - `docs/api/swagger.yaml`
2. ⏳ **각 서버별 Swagger UI 추가**
3. ⏳ **표준 응답 포맷 통일**

### 단기 구현 (3-5일)
1. ⏳ **PHP 라우터 리팩토링**
2. ⏳ **Node.js OpenAPI 미들웨어**
3. ⏳ **Python Flask-RESTX 통합**

### 중기 구현 (1-2주)
1. ⏳ **Java SpringDoc 통합**
2. ⏳ **Go Swaggo 통합**
3. ⏳ **Dashboard API 뷰어**

## 💡 Claude Code 작업 가이드

### 작업 순서
1. **통합 OpenAPI 명세서 먼저 생성** - `docs/api/swagger.yaml`
2. **각 언어별 단계적 적용** - 기존 기능 유지하며 점진적 개선
3. **Dashboard 연동 테스트** - API 호환성 확인
4. **문서화 및 예제** - 개발자 가이드 작성

### 핵심 원칙
- **기존 API 호환성 유지** - 대시보드가 계속 작동해야 함
- **점진적 마이그레이션** - 한 번에 모든 서버 변경 X
- **표준 응답 구조** - success, data, metadata 필드 통일
- **에러 처리 통일** - 일관된 에러 응답 형식

### 예상 효과
✅ **API 문서 자동화** - 수동 문서 관리 불필요
✅ **개발자 경험 향상** - Swagger UI로 직접 테스트 가능
✅ **타입 안전성** - OpenAPI 스펙 기반 코드 생성
✅ **테스트 자동화** - API 계약 테스트 가능
✅ **다국어 일관성** - 모든 서버가 동일한 API 구조

## 📁 파일 구조 변경 예정

```
WebSec-Lab-v2/
├── docs/
│   └── api/
│       ├── swagger.yaml              # 통합 OpenAPI 명세서
│       └── postman-collection.json   # Postman 테스트 컬렉션
├── servers/
│   ├── php-server/
│   │   ├── src/Router/              # 새로운 라우터 클래스
│   │   └── docs/                    # PHP Swagger 문서
│   ├── nodejs-server/
│   │   ├── src/routes/              # OpenAPI 주석이 있는 라우트
│   │   └── swagger.json             # 생성된 Swagger 파일
│   ├── python-server/
│   │   └── src/api/                 # Flask-RESTX 리소스
│   ├── java-server/
│   │   └── src/main/java/com/webseclab/api/  # SpringDoc 컨트롤러
│   └── go-server/
│       └── docs/                    # Swaggo 생성 문서
└── dashboard/
    ├── src/services/ApiClient.js    # 통합 API 클라이언트
    └── src/views/ApiDocs.vue        # Swagger UI 뷰어
```

## 🔧 개발 환경 설정

### Docker Compose 업데이트
```yaml
# docker-compose.yml에 추가
services:
  swagger-ui:
    image: swaggerapi/swagger-ui
    ports:
      - "8084:8080"
    environment:
      SWAGGER_JSON_URL: http://localhost:8080/swagger.json
    volumes:
      - ./docs/api:/usr/share/nginx/html/specs
```

### Makefile 업데이트
```makefile
# 새로운 make 명령어 추가
swagger-generate:
	@echo "Generating Swagger documentation..."
	cd servers/go-server && swag init
	cd servers/nodejs-server && npm run swagger

swagger-ui:
	@echo "Starting Swagger UI..."
	docker run -p 8084:8080 -v $(PWD)/docs/api:/usr/share/nginx/html/specs swaggerapi/swagger-ui

api-test:
	@echo "Running API integration tests..."
	newman run docs/api/postman-collection.json
```

---

이 계획서를 바탕으로 WebSec-Lab v2를 현대적인 API 중심 플랫폼으로 발전시킬 수 있습니다!

**다음 단계**: 통합 OpenAPI 명세서 작성부터 시작하여 단계적으로 각 서버에 적용하면 됩니다.