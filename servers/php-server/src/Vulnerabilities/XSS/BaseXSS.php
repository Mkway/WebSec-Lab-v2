<?php

namespace WebSecLab\Vulnerabilities\XSS;

/**
 * XSS 기본 클래스
 * 모든 XSS 유형의 공통 기능 구현
 */
abstract class BaseXSS implements XSSInterface
{
    protected array $commonPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
        '<body onload=alert("XSS")>',
        '<div style="background:url(javascript:alert(\'XSS\'))">',
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        '<script>console.log("XSS")</script>'
    ];

    /**
     * XSS 패턴 탐지
     */
    public function detectXSS(string $input): bool
    {
        $patterns = [
            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
            '/<iframe\b[^>]*>/i',
            '/javascript:/i',
            '/on\w+\s*=/i',
            '/<svg\b[^>]*>/i',
            '/<img\b[^>]*onerror/i',
            '/<.*?style\s*=.*?javascript:/i'
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 안전한 HTML 이스케이프
     */
    protected function escapeHTML(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    /**
     * 실행 결과 포맷팅
     */
    protected function formatResult(string $output, bool $xssDetected, array $context = []): array
    {
        return [
            'html_output' => $output,
            'raw_output' => strip_tags($output),
            'xss_detected' => $xssDetected,
            'xss_type' => $this->getXSSType(),
            'context' => $context,
            'execution_time' => microtime(true) - ($_SERVER['REQUEST_TIME_FLOAT'] ?? microtime(true)),
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * 기본 테스트 페이로드
     */
    public function getTestPayloads(): array
    {
        return $this->commonPayloads;
    }
}