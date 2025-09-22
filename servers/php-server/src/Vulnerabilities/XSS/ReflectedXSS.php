<?php

namespace WebSecLab\Vulnerabilities\XSS;

/**
 * Reflected XSS 취약점 구현
 * 사용자 입력이 즉시 응답에 반영되는 XSS
 */
class ReflectedXSS extends BaseXSS
{
    public function getXSSType(): string
    {
        return 'reflected';
    }

    /**
     * 취약한 Reflected XSS 코드
     * 사용자 입력을 필터링 없이 직접 출력
     */
    public function executeVulnerable(string $payload, array $context = []): array
    {
        $scenario = $context['scenario'] ?? 'basic';

        switch ($scenario) {
            case 'search':
                $output = $this->vulnerableSearch($payload);
                break;
            case 'greeting':
                $output = $this->vulnerableGreeting($payload);
                break;
            case 'form':
                $output = $this->vulnerableForm($payload, $context);
                break;
            default:
                $output = $this->vulnerableBasic($payload);
        }

        $xssDetected = $this->detectXSS($payload);

        return $this->formatResult($output, $xssDetected, [
            'scenario' => $scenario,
            'payload_length' => strlen($payload),
            'vulnerability_level' => 'high'
        ]);
    }

    /**
     * 안전한 코드 (XSS 방어 적용)
     */
    public function executeSafe(string $payload, array $context = []): array
    {
        $scenario = $context['scenario'] ?? 'basic';

        // 입력값 안전하게 이스케이프
        $safePayload = $this->escapeHTML($payload);

        switch ($scenario) {
            case 'search':
                $output = $this->safeSearch($safePayload);
                break;
            case 'greeting':
                $output = $this->safeGreeting($safePayload);
                break;
            case 'form':
                $output = $this->safeForm($safePayload, $context);
                break;
            default:
                $output = $this->safeBasic($safePayload);
        }

        return $this->formatResult($output, false, [
            'scenario' => $scenario,
            'payload_length' => strlen($payload),
            'vulnerability_level' => 'none',
            'defense_method' => 'html_escape'
        ]);
    }

    // === 취약한 시나리오들 ===

    private function vulnerableBasic(string $input): string
    {
        return "<div class='result'>사용자 입력: {$input}</div>";
    }

    private function vulnerableSearch(string $query): string
    {
        return "<div class='search-result'>
                    <h3>'{$query}'에 대한 검색 결과</h3>
                    <p>검색어: {$query}</p>
                </div>";
    }

    private function vulnerableGreeting(string $name): string
    {
        return "<div class='greeting'>
                    <h2>안녕하세요, {$name}님!</h2>
                    <p>환영합니다: {$name}</p>
                </div>";
    }

    private function vulnerableForm(string $input, array $context): string
    {
        $field = $context['field'] ?? 'input';
        return "<div class='form-result'>
                    <p>입력하신 {$field}: {$input}</p>
                    <input type='text' value='{$input}' readonly>
                </div>";
    }

    // === 안전한 시나리오들 ===

    private function safeBasic(string $input): string
    {
        return "<div class='result'>사용자 입력: {$input}</div>";
    }

    private function safeSearch(string $query): string
    {
        return "<div class='search-result'>
                    <h3>'{$query}'에 대한 검색 결과</h3>
                    <p>검색어: {$query}</p>
                </div>";
    }

    private function safeGreeting(string $name): string
    {
        return "<div class='greeting'>
                    <h2>안녕하세요, {$name}님!</h2>
                    <p>환영합니다: {$name}</p>
                </div>";
    }

    private function safeForm(string $input, array $context): string
    {
        $field = $context['field'] ?? 'input';
        return "<div class='form-result'>
                    <p>입력하신 {$field}: {$input}</p>
                    <input type='text' value='{$input}' readonly>
                </div>";
    }

    /**
     * Reflected XSS 전용 테스트 페이로드
     */
    public function getTestPayloads(): array
    {
        return array_merge(parent::getTestPayloads(), [
            // URL 기반 페이로드
            '?search=<script>alert("Reflected XSS")</script>',

            // 폼 기반 페이로드
            '<input type="text" value="test" onfocus="alert(\'XSS\')">',

            // 속성 이스케이프 우회
            '" onmouseover="alert(\'XSS\')" "',
            '\' onclick=alert("XSS") \'',

            // HTML 엔티티 우회
            '&lt;script&gt;alert("XSS")&lt;/script&gt;',

            // 대소문자 우회
            '<ScRiPt>alert("XSS")</ScRiPt>',

            // 인코딩 우회
            '%3Cscript%3Ealert("XSS")%3C/script%3E'
        ]);
    }
}