import { VulnerabilityUtils } from './common.js';

// XSS 취약점 전용 모듈
export class XSSModule {
    constructor() {
        this.payload = '<script>alert("XSS")</script>';
        this.result = null;
        this.isLoading = false;
        this.liveTestResult = null;
        this.executionStatus = {
            vulnerable: null,
            safe: null
        };
        this.quickPayloads = [
            {
                name: '기본 스크립트',
                icon: '🚀',
                code: '<script>alert("XSS")</script>',
                description: '가장 기본적인 XSS 공격 코드입니다'
            },
            {
                name: '이미지 오류',
                icon: '🖼️',
                code: '<img src=x onerror=alert("XSS")>',
                description: '이미지 로드 실패 시 스크립트를 실행합니다'
            },
            {
                name: 'SVG 로드',
                icon: '🎨',
                code: '<svg onload=alert("XSS")>',
                description: 'SVG 요소 로드 시 스크립트를 실행합니다'
            },
            {
                name: '이벤트 핸들러',
                icon: '👆',
                code: '" onmouseover="alert(\'XSS\')" "',
                description: '마우스 이벤트로 스크립트를 실행합니다'
            },
            {
                name: '대소문자 우회',
                icon: '🔤',
                code: '<ScRiPt>alert("XSS")</ScRiPt>',
                description: '대소문자 혼용으로 필터를 우회합니다'
            },
            {
                name: 'iframe 스크립트',
                icon: '🖥️',
                code: '<iframe src="javascript:alert(\'XSS\')"></iframe>',
                description: 'iframe을 이용한 자바스크립트 실행입니다'
            }
        ];
        this.testProgress = {
            show: false,
            percentage: 0
        };
    }

    // 언어별 XSS 코드 예제
    getCodeExamples(language) {
        const codeExamples = {
            'PHP': {
                vulnerable: `<?php
// 취약한 코드 - XSS 공격에 노출
echo $_GET['input']; // 사용자 입력을 필터링 없이 그대로 출력

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                safe: `<?php
// 안전한 코드 - XSS 공격 방어
echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');

// ✅ 보안 조치:
// 1. htmlspecialchars()로 HTML 이스케이프
// 2. ENT_QUOTES로 따옴표도 변환
// 3. UTF-8 인코딩 명시`
            },
            'Node.js': {
                vulnerable: `// 취약한 코드 - XSS 공격에 노출
app.get('/xss/vulnerable', (req, res) => {
    const input = req.query.input || '';
    // 사용자 입력을 필터링 없이 그대로 출력
    res.send(\`<h1>User Input: \${input}</h1>\`);
});

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                safe: `// 안전한 코드 - XSS 공격 방어
app.get('/xss/safe', (req, res) => {
    const input = req.query.input || '';
    // HTML 이스케이프 처리
    const escapeHtml = (text) => text.replace(/[&<>"']/g,
        (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;',
                  '"': '&quot;', "'": '&#39;' }[m]));
    res.send(\`<h1>User Input: \${escapeHtml(input)}</h1>\`);
});

// ✅ 보안 조치:
// 1. HTML 특수문자 이스케이프
// 2. 악성 스크립트 무력화`
            },
            'Python': {
                vulnerable: `# 취약한 코드 - XSS 공격에 노출
@app.route('/xss/vulnerable')
def xss_vulnerable():
    user_input = request.args.get('input', '')
    # 사용자 입력을 필터링 없이 그대로 출력
    return f'<h1>User Input: {user_input}</h1>'

# ⚠️ 문제점:
# 1. 입력 검증 없음
# 2. HTML 이스케이프 없음
# 3. 악성 스크립트 실행 가능`,
                safe: `# 안전한 코드 - XSS 공격 방어
import html

@app.route('/xss/safe')
def xss_safe():
    user_input = request.args.get('input', '')
    # HTML 이스케이프 처리
    safe_input = html.escape(user_input)
    return f'<h1>User Input: {safe_input}</h1>'

# ✅ 보안 조치:
# 1. html.escape()로 HTML 이스케이프
# 2. 악성 스크립트 무력화`
            },
            'Java': {
                vulnerable: `// 취약한 코드 - XSS 공격에 노출
@GetMapping("/xss/vulnerable")
public String xssVulnerable(@RequestParam String input) {
    // 사용자 입력을 필터링 없이 그대로 출력
    return "<h1>User Input: " + input + "</h1>";
}

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                safe: `// 안전한 코드 - XSS 공격 방어
import org.springframework.web.util.HtmlUtils;

@GetMapping("/xss/safe")
public String xssSafe(@RequestParam String input) {
    // HTML 이스케이프 처리
    String safeInput = HtmlUtils.htmlEscape(input);
    return "<h1>User Input: " + safeInput + "</h1>";
}

// ✅ 보안 조치:
// 1. HtmlUtils.htmlEscape()로 HTML 이스케이프
// 2. 악성 스크립트 무력화`
            },
            'Go': {
                vulnerable: `// 취약한 코드 - XSS 공격에 노출
r.GET("/xss/vulnerable", func(c *gin.Context) {
    input := c.DefaultQuery("input", "")
    // 사용자 입력을 필터링 없이 그대로 출력
    c.Header("Content-Type", "text/html")
    c.String(200, "<h1>User Input: %s</h1>", input)
})

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                safe: `// 안전한 코드 - XSS 공격 방어
import "html"

r.GET("/xss/safe", func(c *gin.Context) {
    input := c.DefaultQuery("input", "")
    // HTML 이스케이프 처리
    safeInput := html.EscapeString(input)
    c.Header("Content-Type", "text/html")
    c.String(200, "<h1>User Input: %s</h1>", safeInput)
})

// ✅ 보안 조치:
// 1. html.EscapeString()로 HTML 이스케이프
// 2. 악성 스크립트 무력화`
            }
        };

        return codeExamples[language] || codeExamples['PHP'];
    }

    // 샘플 페이로드 로드
    loadSamplePayload() {
        const samples = [
            '<script>alert("XSS Test")</script>',
            '<img src=x onerror=alert("IMG XSS")>',
            '<svg onload=alert("SVG XSS")>',
            '"><script>alert("Attribute XSS")</script>',
            'javascript:alert("JavaScript XSS")',
            '<iframe src="javascript:alert(\'IFRAME XSS\')"></iframe>'
        ];
        this.payload = samples[Math.floor(Math.random() * samples.length)];
    }

    // 퀵 페이로드 선택
    selectQuickPayload(payload) {
        this.payload = payload.code;
        VulnerabilityUtils.showSuccessAlert(`${payload.icon} ${payload.name} 페이로드가 선택되었습니다!`);
    }

    // 현재 서버 URL 가져오기
    getCurrentServerUrl(languageServers, selectedLanguage) {
        const server = languageServers[selectedLanguage];
        return `http://localhost:${server.port}`;
    }

    // XSS 엔드포인트 테스트
    async testXSSEndpoints(serverUrl, payload) {
        const results = {
            language: this.selectedLanguage,
            serverUrl: serverUrl,
            payload: payload,
            vulnerable: null,
            safe: null,
            comparison: null
        };

        try {
            // 직접 취약한 엔드포인트 테스트
            const vulnerableUrl = `${serverUrl}/xss/vulnerable?input=${encodeURIComponent(payload)}`;
            const vulnerableResponse = await fetch(vulnerableUrl, { mode: 'cors' });

            if (vulnerableResponse.ok) {
                const vulnerableContent = await vulnerableResponse.text();
                results.vulnerable = {
                    success: true,
                    url: vulnerableUrl,
                    content: vulnerableContent,
                    xssExecuted: vulnerableContent.includes(payload)
                };
            } else {
                results.vulnerable = {
                    success: false,
                    error: `HTTP ${vulnerableResponse.status}`
                };
            }

            // 직접 안전한 엔드포인트 테스트
            const safeUrl = `${serverUrl}/xss/safe?input=${encodeURIComponent(payload)}`;
            const safeResponse = await fetch(safeUrl, { mode: 'cors' });

            if (safeResponse.ok) {
                const safeContent = await safeResponse.text();
                results.safe = {
                    success: true,
                    url: safeUrl,
                    content: safeContent,
                    xssBlocked: !safeContent.includes(payload)
                };
            } else {
                results.safe = {
                    success: false,
                    error: `HTTP ${safeResponse.status}`
                };
            }

            // 비교 분석
            if (results.vulnerable && results.safe) {
                results.comparison = {
                    vulnerabilityDetected: results.vulnerable.xssExecuted,
                    securityImplemented: results.safe.xssBlocked,
                    testSuccessful: results.vulnerable.xssExecuted && results.safe.xssBlocked
                };
            }

            return results;

        } catch (error) {
            console.error(`❌ XSS test failed:`, error);
            return {
                ...results,
                error: error.message
            };
        }
    }

    // 개별 취약한 엔드포인트 테스트
    async testVulnerableEndpoint(languageServers, selectedLanguage) {
        this.isLoading = true;
        this.liveTestResult = null;

        try {
            const serverUrl = this.getCurrentServerUrl(languageServers, selectedLanguage);
            const vulnerableUrl = `${serverUrl}/xss/vulnerable?input=${encodeURIComponent(this.payload)}`;

            const response = await fetch(vulnerableUrl, { mode: 'cors' });
            if (response.ok) {
                const content = await response.text();

                // XSS 공격 성공 여부 감지
                const hasScript = content.includes('<script>') || content.includes('javascript:') || content.includes('onerror=') || content.includes('onload=');
                const isVulnerable = hasScript && content.includes(this.payload);

                if (isVulnerable) {
                    // 실제 XSS 실행을 위해 스크립트 태그를 동적으로 생성
                    this.executeXSSScript(content);
                    this.liveTestResult = `
                        <div class="alert alert-success mb-3">
                            <i class="fas fa-check-circle"></i>
                            <strong>✅ XSS 공격 실행됨!</strong>
                            JavaScript alert가 실행되었습니다.
                        </div>
                        ${content}
                    `;
                } else {
                    this.liveTestResult = content;
                }
            } else {
                this.liveTestResult = `<div class="alert alert-danger">오류: HTTP ${response.status}</div>`;
            }
        } catch (error) {
            this.liveTestResult = `<div class="alert alert-danger">연결 오류: ${error.message}</div>`;
        } finally {
            this.isLoading = false;
        }
    }

    // 개별 안전한 엔드포인트 테스트
    async testSafeEndpoint(languageServers, selectedLanguage) {
        this.isLoading = true;
        this.liveTestResult = null;

        try {
            const serverUrl = this.getCurrentServerUrl(languageServers, selectedLanguage);
            const safeUrl = `${serverUrl}/xss/safe?input=${encodeURIComponent(this.payload)}`;

            const response = await fetch(safeUrl, { mode: 'cors' });
            if (response.ok) {
                const content = await response.text();
                this.liveTestResult = content;
            } else {
                this.liveTestResult = `<div class="alert alert-danger">오류: HTTP ${response.status}</div>`;
            }
        } catch (error) {
            this.liveTestResult = `<div class="alert alert-danger">연결 오류: ${error.message}</div>`;
        } finally {
            this.isLoading = false;
        }
    }

    // XSS 스크립트 실행
    executeXSSScript(content) {
        try {
            // <script> 태그 내용 추출
            const scriptMatch = content.match(/<script[^>]*>(.*?)<\/script>/gi);
            if (scriptMatch) {
                scriptMatch.forEach(scriptTag => {
                    const scriptContent = scriptTag.replace(/<script[^>]*>|<\/script>/gi, '');
                    if (scriptContent.trim()) {
                        eval(scriptContent);
                    }
                });
            }

            // 인라인 이벤트 핸들러 처리 (onerror, onload 등)
            const eventMatches = content.match(/on\w+\s*=\s*['"](.*?)['"]/gi);
            if (eventMatches) {
                eventMatches.forEach(eventHandler => {
                    const jsCode = eventHandler.replace(/on\w+\s*=\s*['"]|['"]/gi, '');
                    if (jsCode.trim()) {
                        eval(jsCode);
                    }
                });
            }

            // javascript: 프로토콜 처리
            const jsProtocolMatch = content.match(/javascript:\s*(.*?)(?=['"\s>])/gi);
            if (jsProtocolMatch) {
                jsProtocolMatch.forEach(jsCode => {
                    const code = jsCode.replace(/javascript:\s*/i, '');
                    if (code.trim()) {
                        eval(code);
                    }
                });
            }
        } catch (error) {
            console.log('XSS 실행 중 오류:', error.message);
            // 에러가 발생해도 일반적인 alert는 실행
            if (this.payload.includes('alert')) {
                const alertMatch = this.payload.match(/alert\s*\(\s*['"`](.*?)['"`]\s*\)/);
                if (alertMatch) {
                    alert(`XSS 공격 성공: ${alertMatch[1]}`);
                } else {
                    alert('XSS 공격이 성공했습니다!');
                }
            }
        }
    }

    // 전체 XSS 테스트 실행
    async executeXSSTest(languageServers, selectedLanguage) {
        this.isLoading = true;
        this.result = null;

        // 테스트 진행 상황 표시 시작
        this.testProgress.show = true;
        this.testProgress.currentStep = 'request';

        // 실행 상태 초기화
        this.executionStatus = {
            vulnerable: null,
            safe: null
        };

        try {
            // 프로그레스 바 시작
            this.testProgress.show = true;
            this.testProgress.percentage = 20;

            console.log('🚀 Sending XSS test request:', this.payload);

            // 프로그레스 업데이트
            this.testProgress.percentage = 60;

            // 선택된 언어 서버로 XSS 테스트 요청
            const serverUrl = this.getCurrentServerUrl(languageServers, selectedLanguage);
            const testResults = await this.testXSSEndpoints(serverUrl, this.payload);

            console.log('✅ XSS test results:', testResults);

            // 프로그레스 완료
            this.testProgress.percentage = 100;
            await VulnerabilityUtils.delay(300);

            this.result = {
                success: true,
                data: testResults
            };

            // 성공 알림
            VulnerabilityUtils.showSuccessAlert('🎉 XSS 보안 테스트가 완료되었습니다!');

            // 코드 하이라이팅 업데이트
            VulnerabilityUtils.updateCodeHighlighting();

        } catch (error) {
            console.error('❌ XSS test failed:', error);

            this.result = {
                success: false,
                error: error.message,
                details: error.toString()
            };

            // 에러 알림
            VulnerabilityUtils.showErrorAlert(`❌ 테스트 실행 실패: ${error.message}`);
        } finally {
            this.isLoading = false;
            // 3초 후 진행 상황 숨기기
            setTimeout(() => {
                this.testProgress.show = false;
            }, 3000);
        }
    }
}

// 전역 인스턴스 생성
export const xssModule = new XSSModule();