<?php

namespace WebSecLab\Controllers;

/**
 * Base Controller Class
 * 모든 컨트롤러의 공통 기능 제공
 */
abstract class BaseController
{
    /**
     * JSON 응답 생성
     */
    protected function jsonResponse(array $data, int $statusCode = 200): string
    {
        http_response_code($statusCode);
        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }

    /**
     * 성공 응답 생성
     */
    protected function successResponse(array $data = []): string
    {
        return $this->jsonResponse([
            'success' => true,
            'server' => 'PHP',
            'timestamp' => date('c'),
            ...$data
        ]);
    }

    /**
     * 에러 응답 생성
     */
    protected function errorResponse(string $message, int $statusCode = 400, array $data = []): string
    {
        return $this->jsonResponse([
            'success' => false,
            'error' => true,
            'message' => $message,
            'server' => 'PHP',
            'timestamp' => date('c'),
            ...$data
        ], $statusCode);
    }

    /**
     * 취약점 테스트 응답 템플릿
     */
    protected function vulnerabilityResponse(
        string $vulnerability,
        string $payload,
        string $mode,
        array $result,
        array $analysis = []
    ): string {
        return $this->successResponse([
            'vulnerability' => $vulnerability,
            'payload' => $payload,
            'mode' => $mode,
            'result' => $result,
            'analysis' => $analysis
        ]);
    }

    /**
     * 입력값 검증
     */
    protected function validateInput(array $input, array $required = []): bool
    {
        foreach ($required as $field) {
            if (!isset($input[$field]) || empty($input[$field])) {
                throw new \InvalidArgumentException("Required field '{$field}' is missing");
            }
        }
        return true;
    }

    /**
     * SQL 인젝션 방지를 위한 입력값 정리 (안전한 모드용)
     */
    protected function sanitizeInput(string $input): string
    {
        // 기본적인 SQL 인젝션 문자 제거
        $input = str_replace(["'", '"', ';', '--', '/*', '*/', 'UNION', 'SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE'], '', $input);
        return trim($input);
    }

    /**
     * XSS 방지를 위한 HTML 인코딩 (안전한 모드용)
     */
    protected function escapeHtml(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * 실행 시간 측정
     */
    protected function measureExecutionTime(callable $callback): array
    {
        $startTime = microtime(true);
        $result = $callback();
        $executionTime = microtime(true) - $startTime;
        
        return [
            'result' => $result,
            'execution_time' => round($executionTime, 4)
        ];
    }

    /**
     * 로그 기록
     */
    protected function log(string $level, string $message, array $context = []): void
    {
        $logData = [
            'timestamp' => date('c'),
            'level' => $level,
            'message' => $message,
            'server' => 'PHP',
            'context' => $context
        ];
        
        error_log(json_encode($logData));
    }
}