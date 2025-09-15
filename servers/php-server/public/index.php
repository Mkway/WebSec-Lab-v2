<?php
/**
 * WebSec-Lab v2 PHP Server
 * Entry Point for PHP Vulnerability Testing Server
 */

require_once __DIR__ . '/../vendor/autoload.php';

use WebSecLab\Controllers\VulnerabilityController;
use WebSecLab\Controllers\HealthController;
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
            
        case 'vulnerabilities':
            if (!isset($pathParts[1])) {
                throw new Exception('Vulnerability type not specified');
            }
            
            $controller = new VulnerabilityController();
            $vulnerabilityType = $pathParts[1];
            
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
                    'GET /vulnerabilities' => 'List available vulnerability tests',
                    'POST /vulnerabilities/{type}' => 'Execute vulnerability test'
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