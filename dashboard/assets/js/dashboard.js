const { createApp } = Vue;

createApp({
    data() {
        return {
            serverStatus: 'Connected',
            phpStatus: 'Running',
            activeVuln: 'xss',
            selectedLanguage: 'PHP',
            isLoading: false,

            // 언어별 서버 정보
            languageServers: {
                'PHP': {
                    name: 'PHP',
                    port: 8080,
                    status: 'unknown',
                    icon: '🐘',
                    color: '#4F5B93',
                    vulnerableCode: `<?php
// 취약한 코드 - XSS 공격에 노출
echo $_GET['input']; // 사용자 입력을 필터링 없이 그대로 출력

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                    safeCode: `<?php
// 안전한 코드 - XSS 공격 방어
echo htmlspecialchars($_GET['input'], ENT_QUOTES, 'UTF-8');

// ✅ 보안 조치:
// 1. htmlspecialchars()로 HTML 이스케이프
// 2. ENT_QUOTES로 따옴표도 변환
// 3. UTF-8 인코딩 명시`
                },
                'Node.js': {
                    name: 'Node.js',
                    port: 3000,
                    status: 'unknown',
                    icon: '💚',
                    color: '#68A063',
                    vulnerableCode: `// 취약한 코드 - XSS 공격에 노출
app.get('/xss/vulnerable', (req, res) => {
    const input = req.query.input || '';
    // 사용자 입력을 필터링 없이 그대로 출력
    res.send(\`<h1>User Input: \${input}</h1>\`);
});

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                    safeCode: `// 안전한 코드 - XSS 공격 방어
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
                    name: 'Python',
                    port: 5000,
                    status: 'unknown',
                    icon: '🐍',
                    color: '#3776AB',
                    vulnerableCode: `# 취약한 코드 - XSS 공격에 노출
@app.route('/xss/vulnerable')
def xss_vulnerable():
    user_input = request.args.get('input', '')
    # 사용자 입력을 필터링 없이 그대로 출력
    return f'<h1>User Input: {user_input}</h1>'

# ⚠️ 문제점:
# 1. 입력 검증 없음
# 2. HTML 이스케이프 없음
# 3. 악성 스크립트 실행 가능`,
                    safeCode: `# 안전한 코드 - XSS 공격 방어
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
                    name: 'Java',
                    port: 8081,
                    status: 'unknown',
                    icon: '☕',
                    color: '#ED8B00',
                    vulnerableCode: `// 취약한 코드 - XSS 공격에 노출
@GetMapping("/xss/vulnerable")
public String xssVulnerable(@RequestParam String input) {
    // 사용자 입력을 필터링 없이 그대로 출력
    return "<h1>User Input: " + input + "</h1>";
}

// ⚠️ 문제점:
// 1. 입력 검증 없음
// 2. HTML 이스케이프 없음
// 3. 악성 스크립트 실행 가능`,
                    safeCode: `// 안전한 코드 - XSS 공격 방어
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
                    name: 'Go',
                    port: 8082,
                    status: 'unknown',
                    icon: '🐹',
                    color: '#00ADD8',
                    vulnerableCode: `// 취약한 코드 - XSS 공격에 노출
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
                    safeCode: `// 안전한 코드 - XSS 공격 방어
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
            },
            // 카테고리별 그룹화된 취약점 목록 (VULNERABILITY_PRIORITY.md 기반)
            vulnerabilityCategories: [
                {
                    id: 'injection-attacks',
                    name: '💉 Injection Attacks',
                    priority: 'high',
                    icon: 'fas fa-syringe',
                    description: '코드/쿼리 주입 공격',
                    vulnerabilities: [
                        { type: 'sql-injection', name: 'SQL Injection', icon: 'fas fa-database', status: 'completed', progress: 20, languages: ['PHP'] },
                        { type: 'xss', name: 'XSS', icon: 'fas fa-code', status: 'completed', progress: 100, languages: ['PHP', 'Node.js', 'Python', 'Java', 'Go'] },
                        { type: 'command-injection', name: 'Command Injection', icon: 'fas fa-terminal', status: 'planned', progress: 0, languages: [] },
                        { type: 'nosql-injection', name: 'NoSQL Injection', icon: 'fas fa-leaf', status: 'planned', progress: 0, languages: [] }
                    ]
                },
                {
                    id: 'file-system-attacks',
                    name: '📁 File System Attacks',
                    priority: 'high',
                    icon: 'fas fa-folder-open',
                    description: '파일 시스템 공격',
                    vulnerabilities: [
                        { type: 'file-upload', name: 'File Upload', icon: 'fas fa-upload', status: 'planned', progress: 0, languages: [] },
                        { type: 'directory-traversal', name: 'Path Traversal', icon: 'fas fa-route', status: 'planned', progress: 0, languages: [] },
                        { type: 'file-inclusion', name: 'File Inclusion', icon: 'fas fa-file-import', status: 'planned', progress: 0, languages: [] }
                    ]
                },
                {
                    id: 'web-security-bypass',
                    name: '🌐 Web Security Bypass',
                    priority: 'medium',
                    icon: 'fas fa-shield-alt',
                    description: '웹 보안 메커니즘 우회',
                    vulnerabilities: [
                        { type: 'csrf', name: 'CSRF', icon: 'fas fa-exchange-alt', status: 'planned', progress: 0, languages: [] },
                        { type: 'ssti', name: 'SSTI', icon: 'fas fa-code-branch', status: 'planned', progress: 0, languages: [] },
                        { type: 'xxe', name: 'XXE', icon: 'fas fa-file-code', status: 'planned', progress: 0, languages: [] },
                        { type: 'ssrf', name: 'SSRF', icon: 'fas fa-network-wired', status: 'planned', progress: 0, languages: [] }
                    ]
                },
                {
                    id: 'advanced-attacks',
                    name: '🔓 Advanced Attacks',
                    priority: 'low',
                    icon: 'fas fa-lock-open',
                    description: '고급 공격 기법',
                    vulnerabilities: [
                        { type: 'deserialization', name: 'Insecure Deserialization', icon: 'fas fa-unlink', status: 'planned', progress: 0, languages: [] },
                        { type: 'ldap-injection', name: 'LDAP Injection', icon: 'fas fa-building', status: 'planned', progress: 0, languages: [] },
                        { type: 'xpath-injection', name: 'XPath Injection', icon: 'fas fa-sitemap', status: 'planned', progress: 0, languages: [] }
                    ]
                }
            ],

            // 현재 활성화된 카테고리
            activeCategory: 'injection-attacks',

            // 개별 취약점 호환성을 위한 플랫 리스트
            vulnerabilities: [],
            xssPayload: '<script>alert("XSS")</script>',
            xssMode: 'both',
            xssScenario: 'basic',
            xssResult: null,
            xssExecutionStatus: {
                vulnerable: null,
                safe: null
            },
            quickPayloads: [
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
            ],
            testProgress: {
                show: false,
                percentage: 0
            },
            liveTestResult: null
        };
    },
    mounted() {
        this.initializeVulnerabilities();
        this.checkServerStatus();
        this.checkAllLanguageServers();
        this.loadServerInfo();
        this.setupMessageListener();
        this.initializePrism();
    },
    methods: {
        initializeVulnerabilities() {
            // 카테고리별 취약점을 플랫 리스트로 변환
            this.vulnerabilities = [];
            this.vulnerabilityCategories.forEach(category => {
                this.vulnerabilities.push(...category.vulnerabilities);
            });
        },
        selectVulnerability(type) {
            this.activeVuln = type;
            this.xssResult = null;
        },

        // 언어 선택 기능
        selectLanguage(language) {
            this.selectedLanguage = language;
            this.xssResult = null;
            console.log(`✅ Selected language: ${language}`);
        },

        // 언어별 Prism.js 클래스 매핑
        getLanguageClass(language) {
            const languageMap = {
                'PHP': 'php',
                'Node.js': 'javascript',
                'Python': 'python',
                'Java': 'java',
                'Go': 'go'
            };
            return languageMap[language] || 'javascript';
        },

        // 개별 취약한 엔드포인트 테스트
        async testVulnerableEndpoint() {
            this.isLoading = true;
            this.liveTestResult = null;

            try {
                const serverUrl = this.getCurrentServerUrl();
                const vulnerableUrl = `${serverUrl}/xss/vulnerable?input=${encodeURIComponent(this.xssPayload)}`;

                const response = await fetch(vulnerableUrl, { mode: 'cors' });
                if (response.ok) {
                    const content = await response.text();

                    // XSS 공격 성공 여부 감지
                    const hasScript = content.includes('<script>') || content.includes('javascript:') || content.includes('onerror=') || content.includes('onload=');
                    const isVulnerable = hasScript && content.includes(this.xssPayload);

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
        },

        // 개별 안전한 엔드포인트 테스트
        async testSafeEndpoint() {
            this.isLoading = true;
            this.liveTestResult = null;

            try {
                const serverUrl = this.getCurrentServerUrl();
                const safeUrl = `${serverUrl}/xss/safe?input=${encodeURIComponent(this.xssPayload)}`;

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
        },

        // 모든 언어 서버 상태 확인
        async checkAllLanguageServers() {
            for (const [language, server] of Object.entries(this.languageServers)) {
                await this.checkLanguageServerStatus(language);
            }
        },

        // 개별 언어 서버 상태 확인
        async checkLanguageServerStatus(language) {
            const server = this.languageServers[language];

            try {
                // 실제 서버에 헬스체크 요청
                const serverUrl = `http://localhost:${server.port}`;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);

                const response = await fetch(`${serverUrl}/`, {
                    mode: 'cors',
                    signal: controller.signal
                });

                clearTimeout(timeoutId);

                if (response.ok) {
                    server.status = 'running';
                    console.log(`✅ Server ${language}: running`);
                } else {
                    server.status = 'offline';
                    console.log(`❌ Server ${language}: offline (HTTP ${response.status})`);
                }
            } catch (error) {
                if (error.name === 'AbortError') {
                    console.log(`⏰ Server ${language}: timeout`);
                } else {
                    console.log(`❌ Server ${language} health check failed:`, error.message);
                }
                server.status = 'offline';
            }
        },

        // 현재 선택된 언어의 서버 URL 가져오기
        getCurrentServerUrl() {
            const server = this.languageServers[this.selectedLanguage];
            return `http://localhost:${server.port}`;
        },

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
                console.error(`❌ XSS test failed for ${this.selectedLanguage}:`, error);
                return {
                    ...results,
                    error: error.message
                };
            }
        },
        getVulnName(type) {
            // vulnerabilities 배열이 아직 초기화되지 않았다면 카테고리에서 직접 찾기
            if (!this.vulnerabilities.length) {
                for (const category of this.vulnerabilityCategories) {
                    const vuln = category.vulnerabilities.find(v => v.type === type);
                    if (vuln) return vuln.name;
                }
            }

            const vuln = this.vulnerabilities.find(v => v.type === type);
            return vuln ? vuln.name : type.toUpperCase();
        },
        async checkServerStatus() {
            try {
                const response = await fetch('/api/health');
                if (response.ok) {
                    this.serverStatus = 'Connected';
                    this.phpStatus = 'Running';
                } else {
                    this.serverStatus = 'Error';
                    this.phpStatus = 'Error';
                }
            } catch (error) {
                this.serverStatus = 'Disconnected';
                this.phpStatus = 'Offline';
                console.error('Server connection failed:', error);
            }
        },
        async loadServerInfo() {
            try {
                const response = await fetch('/api/');
                if (response.ok) {
                    const data = await response.json();
                    console.log('Server info loaded:', data);
                }
            } catch (error) {
                console.error('Failed to load server info:', error);
            }
        },
        loadSamplePayload() {
            const samples = [
                '<script>alert("XSS Test")</script>',
                '<img src=x onerror=alert("IMG XSS")>',
                '<svg onload=alert("SVG XSS")>',
                '"><script>alert("Attribute XSS")</script>',
                'javascript:alert("JavaScript XSS")',
                '<iframe src="javascript:alert(\'IFRAME XSS\')"></iframe>'
            ];
            this.xssPayload = samples[Math.floor(Math.random() * samples.length)];
        },
        async executeXSSTest() {
            this.isLoading = true;
            this.xssResult = null;

            // 테스트 진행 상황 표시 시작
            this.testProgress.show = true;
            this.testProgress.currentStep = 'request';

            // 실행 상태 초기화
            this.xssExecutionStatus = {
                vulnerable: null,
                safe: null
            };

            try {
                // 프로그레스 바 시작
                this.testProgress.show = true;
                this.testProgress.percentage = 20;

                console.log('🚀 Sending XSS test request:', this.xssPayload);

                // 프로그레스 업데이트
                this.testProgress.percentage = 60;

                // 선택된 언어 서버로 XSS 테스트 요청
                const serverUrl = this.getCurrentServerUrl();
                const testResults = await this.testXSSEndpoints(serverUrl, this.xssPayload);

                console.log('✅ XSS test results:', testResults);

                // 프로그레스 완료
                this.testProgress.percentage = 100;
                await this.delay(300);

                this.xssResult = {
                    success: true,
                    data: testResults
                };

                // 성공 알림
                this.showSuccessAlert('🎉 XSS 보안 테스트가 완료되었습니다!');

                // 코드 하이라이팅 업데이트
                this.updateCodeHighlighting();

            } catch (error) {
                console.error('❌ XSS test failed:', error);

                this.xssResult = {
                    success: false,
                    error: error.message,
                    details: error.toString()
                };

                // 에러 알림
                this.showErrorAlert(`❌ 테스트 실행 실패: ${error.message}`);
            } finally {
                this.isLoading = false;
                // 3초 후 진행 상황 숨기기
                setTimeout(() => {
                    this.testProgress.show = false;
                }, 3000);
            }
        },

        // 사용자 친화적 기능들
        selectQuickPayload(payload) {
            this.xssPayload = payload.code;
            this.showSuccessAlert(`${payload.icon} ${payload.name} 페이로드가 선택되었습니다!`);
        },

        updateProgressStep(step) {
            this.testProgress.currentStep = step;
        },

        getStepClass(step) {
            const currentIndex = this.testProgress.steps.indexOf(this.testProgress.currentStep);
            const stepIndex = this.testProgress.steps.indexOf(step);

            if (stepIndex < currentIndex) {
                return 'completed';
            } else if (stepIndex === currentIndex) {
                return 'active';
            } else {
                return 'pending';
            }
        },
        getProgressWidth() {
            const currentIndex = this.testProgress.steps.indexOf(this.testProgress.currentStep);
            const totalSteps = this.testProgress.steps.length - 1;
            return Math.round((currentIndex / totalSteps) * 100);
        },

        delay(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },

        // Phase 2: Code Highlighting and Display Enhancement
        initializePrism() {
            // Prism.js 초기화 및 설정
            this.$nextTick(() => {
                if (window.Prism) {
                    // 모든 코드 블록에 라인 넘버 추가
                    document.querySelectorAll('pre.line-numbers').forEach(pre => {
                        pre.classList.add('line-numbers');
                    });

                    // Prism 하이라이트 재실행
                    Prism.highlightAll();

                    // 코드 복사 버튼 추가
                    this.addCopyButtons();
                }
            });
        },

        addCopyButtons() {
            // 각 코드 섹션에 복사 버튼 추가
            document.querySelectorAll('.code-section').forEach(section => {
                if (!section.querySelector('.code-copy-btn')) {
                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'code-copy-btn';
                    copyBtn.innerHTML = '<i class="fas fa-copy"></i> 복사';
                    copyBtn.addEventListener('click', () => {
                        const codeElement = section.querySelector('code');
                        if (codeElement) {
                            this.copyCodeToClipboard(codeElement.textContent);
                        }
                    });
                    section.appendChild(copyBtn);
                }
            });
        },

        copyCodeToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                this.showSuccessAlert('📋 코드가 클립보드에 복사되었습니다!');
            }).catch(() => {
                // Fallback for older browsers
                const textarea = document.createElement('textarea');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                this.showSuccessAlert('📋 코드가 클립보드에 복사되었습니다!');
            });
        },

        updateCodeHighlighting() {
            // 동적으로 추가된 코드 블록의 하이라이트 업데이트
            this.$nextTick(() => {
                if (window.Prism) {
                    Prism.highlightAll();
                    this.addCopyButtons();
                }
            });
        },
        getRiskClass(level) {
            switch (level?.toLowerCase()) {
                case 'high':
                case 'critical':
                    return 'badge bg-danger';
                case 'medium':
                    return 'badge bg-warning';
                case 'low':
                    return 'badge bg-info';
                default:
                    return 'badge bg-secondary';
            }
        },
        setupMessageListener() {
            // iframe에서 오는 메시지 수신
            window.addEventListener('message', (event) => {
                if (event.data.type === 'xss_result') {
                    if (event.data.mode === 'vulnerable') {
                        this.xssExecutionStatus.vulnerable = event.data.executed;
                    } else if (event.data.mode === 'safe') {
                        this.xssExecutionStatus.safe = event.data.executed;
                    }
                    console.log('XSS Execution Status:', event.data);
                } else if (event.data.type === 'xss_executed') {
                    console.log('XSS Alert Executed:', event.data.message);
                    // 실제 XSS 실행 알림
                    this.showXSSAlert(event.data.message);
                }
            });
        },
        getVulnerableDemoUrl() {
            if (!this.xssPayload) return '';
            const params = new URLSearchParams({
                scenario: this.xssScenario,
                mode: 'vulnerable',
                payload: this.xssPayload
            });
            return `/api/demo/?${params.toString()}`;
        },
        getSafeDemoUrl() {
            if (!this.xssPayload) return '';
            const params = new URLSearchParams({
                scenario: this.xssScenario,
                mode: 'safe',
                payload: this.xssPayload
            });
            return `/api/demo/?${params.toString()}`;
        },
        onIframeLoad(type) {
            console.log(`${type} iframe loaded`);
            // iframe 로드 후 실행 상태 초기화
            if (type === 'vulnerable') {
                this.xssExecutionStatus.vulnerable = null;
            } else {
                this.xssExecutionStatus.safe = null;
            }
        },
        showXSSAlert(message) {
            // XSS 실행 알림 표시 (실제 alert 대신 안전한 방식으로)
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
            alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            alertDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <strong>XSS 실행됨!</strong><br>
                메시지: ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);

            // 5초 후 자동 제거
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 5000);
        },

        executeXSSScript(content) {
            // 서버 응답에서 스크립트 추출 및 실행
            try {
                // <script> 태그 내용 추출
                const scriptMatch = content.match(/<script[^>]*>(.*?)<\/script>/gi);
                if (scriptMatch) {
                    scriptMatch.forEach(scriptTag => {
                        const scriptContent = scriptTag.replace(/<script[^>]*>|<\/script>/gi, '');
                        if (scriptContent.trim()) {
                            // 실제 JavaScript 실행
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
                if (this.xssPayload.includes('alert')) {
                    const alertMatch = this.xssPayload.match(/alert\s*\(\s*['"`](.*?)['"`]\s*\)/);
                    if (alertMatch) {
                        alert(`XSS 공격 성공: ${alertMatch[1]}`);
                    } else {
                        alert('XSS 공격이 성공했습니다!');
                    }
                }
            }
        },

        showXSSSuccessAlert() {
            // XSS 공격 성공 알림
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-warning alert-dismissible fade show position-fixed';
            alertDiv.style.cssText = 'top: 140px; right: 20px; z-index: 10001; min-width: 400px; max-width: 500px; box-shadow: 0 8px 32px rgba(255, 193, 7, 0.4);';
            alertDiv.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="me-3">
                        <i class="fas fa-bug fa-2x text-warning"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="fw-bold text-warning mb-1">
                            <i class="fas fa-exclamation-triangle"></i> XSS 취약점 발견!
                        </div>
                        <div class="small text-warning-emphasis">
                            스크립트가 서버 응답에 포함되었습니다.<br>
                            실제 브라우저에서는 JavaScript가 실행됩니다.
                        </div>
                    </div>
                    <button type="button" class="btn-close btn-close-warning" data-bs-dismiss="alert"></button>
                </div>
            `;
            document.body.appendChild(alertDiv);

            // 진입 애니메이션
            alertDiv.style.transform = 'translateX(100%)';
            alertDiv.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';

            setTimeout(() => {
                alertDiv.style.transform = 'translateX(0)';
            }, 10);

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.style.transform = 'translateX(100%)';
                    setTimeout(() => {
                        if (alertDiv.parentNode) {
                            alertDiv.parentNode.removeChild(alertDiv);
                        }
                    }, 500);
                }
            }, 7000);
        },
        showSuccessAlert(message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-success alert-dismissible fade show position-fixed';
            alertDiv.style.cssText = 'top: 80px; right: 20px; z-index: 10000; min-width: 350px; max-width: 500px; box-shadow: 0 8px 32px rgba(40, 167, 69, 0.3);';
            alertDiv.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="me-3">
                        <i class="fas fa-check-circle fa-2x text-success"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="fw-bold text-success mb-1">
                            <i class="fas fa-sparkles"></i> 작업 성공!
                        </div>
                        <div class="small text-success-emphasis">
                            ${message}
                        </div>
                    </div>
                    <button type="button" class="btn-close btn-close-success" data-bs-dismiss="alert"></button>
                </div>
            `;
            document.body.appendChild(alertDiv);

            // 진입 애니메이션
            alertDiv.style.transform = 'translateX(100%)';
            alertDiv.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';

            setTimeout(() => {
                alertDiv.style.transform = 'translateX(0)';
            }, 10);

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.style.transform = 'translateX(100%)';
                    setTimeout(() => {
                        if (alertDiv.parentNode) {
                            alertDiv.parentNode.removeChild(alertDiv);
                        }
                    }, 500);
                }
            }, 4000);
        },
        showErrorAlert(message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
            alertDiv.style.cssText = 'top: 80px; right: 20px; z-index: 10000; min-width: 350px; max-width: 500px; box-shadow: 0 8px 32px rgba(220, 53, 69, 0.3);';
            alertDiv.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="me-3">
                        <i class="fas fa-exclamation-triangle fa-2x text-danger"></i>
                    </div>
                    <div class="flex-grow-1">
                        <div class="fw-bold text-danger mb-1">
                            <i class="fas fa-bug"></i> 오류 발생!
                        </div>
                        <div class="small text-danger-emphasis">
                            ${message}
                        </div>
                    </div>
                    <button type="button" class="btn-close btn-close-danger" data-bs-dismiss="alert"></button>
                </div>
            `;
            document.body.appendChild(alertDiv);

            // 진입 애니메이션 (에러는 약간 흔들림 효과 추가)
            alertDiv.style.transform = 'translateX(100%)';
            alertDiv.style.transition = 'all 0.5s cubic-bezier(0.4, 0, 0.2, 1)';

            setTimeout(() => {
                alertDiv.style.transform = 'translateX(0)';
                // 에러 알림에는 약간의 흔들림 추가
                setTimeout(() => {
                    alertDiv.style.animation = 'dangerShake 0.5s ease-in-out';
                }, 200);
            }, 10);

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.style.transform = 'translateX(100%)';
                    setTimeout(() => {
                        if (alertDiv.parentNode) {
                            alertDiv.parentNode.removeChild(alertDiv);
                        }
                    }, 500);
                }
            }, 6000);
        },
        // Utility methods for future vulnerability types
        async executeSQLTest() {
            // TODO: Implement SQL injection testing
            console.log('SQL injection test not implemented yet');
        },
        async executeCommandTest() {
            // TODO: Implement command injection testing
            console.log('Command injection test not implemented yet');
        }
    }
}).mount('#app');