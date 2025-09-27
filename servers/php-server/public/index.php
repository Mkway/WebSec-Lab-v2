<?php
/**
 * WebSec-Lab v2 PHP Server
 * Entry Point for PHP Vulnerability Testing Server
 */

require_once __DIR__ . '/../vendor/autoload.php';

use WebSecLab\Controllers\VulnerabilityController;
use WebSecLab\Controllers\XSSController;
use WebSecLab\Controllers\HealthController;
use WebSecLab\Controllers\SwaggerController;
use WebSecLab\Utils\DatabaseManager;

// CORS 헤더 설정
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

// OPTIONS 요청 처리 (Preflight)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// 환경 변수 로드
if (file_exists(__DIR__ . '/../.env')) {
    $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
    $dotenv->load();
}

// 라우팅 처리
$requestUri = $_SERVER['REQUEST_URI'];
$requestMethod = $_SERVER['REQUEST_METHOD'];

// URL 파싱
$path = parse_url($requestUri, PHP_URL_PATH);
$pathParts = explode('/', trim($path, '/'));

try {
    switch ($pathParts[0]) {
        case 'health':
            $controller = new HealthController();
            echo $controller->check();
            break;

        case 'swagger.json':
            $swaggerController = new SwaggerController();
            echo $swaggerController->generateSwaggerJson();
            break;

        case 'swagger-ui':
        case 'docs':
            $swaggerController = new SwaggerController();
            header('Content-Type: text/html');
            echo $swaggerController->serveSwaggerUI();
            break;

        case 'xss':
            // 간단한 XSS 테스트 엔드포인트 (다른 서버들과 호환)
            header('Content-Type: text/html');
            $input = $_GET['input'] ?? '<script>alert("XSS")</script>';

            if (isset($pathParts[1]) && $pathParts[1] === 'safe') {
                // 안전한 엔드포인트 - HTML 이스케이프
                echo '<h1>User Input: ' . htmlspecialchars($input, ENT_QUOTES, 'UTF-8') . '</h1>';
            } else {
                // 취약한 엔드포인트 - 직접 출력
                echo '<h1>User Input: ' . $input . '</h1>';
            }
            break;
            
        case 'vulnerabilities':
            if (!isset($pathParts[1])) {
                $controller = new VulnerabilityController();
                echo $controller->listVulnerabilities();
                break;
            }

            $vulnerabilityType = $pathParts[1];

            // XSS 전용 라우팅
            if ($vulnerabilityType === 'xss') {
                $xssController = new XSSController();

                switch ($requestMethod) {
                    case 'POST':
                        if (isset($pathParts[2])) {
                            switch ($pathParts[2]) {
                                case 'reflected':
                                    echo $xssController->testReflectedXSS();
                                    break;
                                default:
                                    echo $xssController->testReflectedXSS();
                            }
                        } else {
                            echo $xssController->testReflectedXSS();
                        }
                        break;
                    case 'GET':
                        if (isset($pathParts[2])) {
                            switch ($pathParts[2]) {
                                case 'payloads':
                                    echo $xssController->getPayloads();
                                    break;
                                case 'scenarios':
                                    echo $xssController->getScenarios();
                                    break;
                                default:
                                    echo $xssController->getScenarios();
                            }
                        } else {
                            echo $xssController->getScenarios();
                        }
                        break;
                    default:
                        throw new Exception('Method not allowed');
                }
                break;
            }

            // 기타 취약점 타입
            $controller = new VulnerabilityController();

            switch ($requestMethod) {
                case 'GET':
                    echo $controller->listVulnerabilities();
                    break;
                case 'POST':
                    $input = json_decode(file_get_contents('php://input'), true);
                    echo $controller->executeVulnerabilityTest($vulnerabilityType, $input);
                    break;
                default:
                    throw new Exception('Method not allowed');
            }
            break;
            
        default:
            // 기본 응답
            echo json_encode([
                'server' => 'PHP',
                'version' => '2.0.0',
                'status' => 'running',
                'endpoints' => [
                    'GET /health' => 'Health check',
                    'GET /swagger.json' => 'OpenAPI specification',
                    'GET /swagger-ui' => 'Swagger UI documentation',
                    'GET /docs' => 'API documentation (alias for swagger-ui)',
                    'GET /vulnerabilities' => 'List available vulnerability tests',
                    'POST /vulnerabilities/{type}' => 'Execute vulnerability test',
                    'POST /vulnerabilities/xss' => 'Execute XSS test',
                    'GET /vulnerabilities/xss/payloads' => 'Get XSS payloads',
                    'GET /vulnerabilities/xss/scenarios' => 'Get XSS scenarios'
                ],
                'available_vulnerabilities' => [
                    'sql-injection',
                    'xss',
                    'command-injection',
                    'file-upload',
                    'directory-traversal',
                    'object-injection'
                ]
            ]);
            break;
    }
} catch (Exception $e) {
    http_response_code(400);
    echo json_encode([
        'error' => true,
        'message' => $e->getMessage(),
        'server' => 'PHP'
    ]);
} catch (Error $e) {
    http_response_code(500);
    echo json_encode([
        'error' => true,
        'message' => 'Internal server error',
        'server' => 'PHP'
    ]);
}