// SQL Injection Page Component
import { languageServers } from '../config/servers.js?v=6';
import { VulnerabilityUtils } from '../vulnerabilities/common.js?v=6';
import { sqlInjectionModule } from '../vulnerabilities/sql-injection.js?v=9';

export const SQLInjectionPage = {
    currentLanguage: 'PHP',
    sqlPayload: "' OR '1'='1",
    testResults: null,
    isLoading: false,

    async render() {
        return `
            <div class="sql-injection-page">
                <!-- Page Header -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <div class="page-header">
                            <h1><i class="fas fa-database text-primary"></i> SQL Injection</h1>
                            <p class="lead">데이터베이스 쿼리 주입 공격을 통한 데이터 유출 및 우회 기법 학습</p>
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

                <!-- Testing Interface -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5><i class="fas fa-vial"></i> SQL 주입 테스트</h5>
                                <span class="badge bg-info">현재: ${this.currentLanguage}</span>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-8">
                                        <div class="mb-3">
                                            <label class="form-label">SQL Injection Payload</label>
                                            <div class="input-group">
                                                <input type="text" class="form-control font-monospace"
                                                       id="sql-payload" value="${this.sqlPayload}"
                                                       placeholder="SQL 주입 페이로드 입력">
                                                <button class="btn btn-outline-secondary" onclick="SQLInjectionPage.loadRandomPayload()">
                                                    <i class="fas fa-random"></i> 랜덤
                                                </button>
                                            </div>
                                            <div class="form-text">예: ' OR '1'='1, '; DROP TABLE users; --</div>
                                        </div>
                                        <div class="mb-3">
                                            <div class="btn-group">
                                                <button class="btn btn-danger" onclick="SQLInjectionPage.testVulnerableEndpoint()"
                                                        id="test-vulnerable-btn">
                                                    <i class="fas fa-bug"></i> 취약한 코드 테스트
                                                </button>
                                                <button class="btn btn-success" onclick="SQLInjectionPage.testSafeEndpoint()"
                                                        id="test-safe-btn">
                                                    <i class="fas fa-shield-alt"></i> 보안 코드 테스트
                                                </button>
                                                <button class="btn btn-primary" onclick="SQLInjectionPage.runComparisonTest()"
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
                                        <div class="spinner-border text-primary" role="status">
                                            <span class="visually-hidden">테스트 중...</span>
                                        </div>
                                        <p class="mt-2">SQL 주입 테스트 실행 중...</p>
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
                                <h5><i class="fas fa-book"></i> SQL Injection 가이드</h5>
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
                    onclick="SQLInjectionPage.selectLanguage('${name}')"
                    data-language="${name}">
                <span style="color: ${server.color};">${server.icon}</span>
                ${server.name}
            </button>
        `).join('');
    },

    renderQuickPayloads() {
        const payloads = [
            { name: 'OR 1=1', payload: "' OR '1'='1", desc: '기본 우회' },
            { name: 'Union Select', payload: "' UNION SELECT null,null,null--", desc: '데이터 조합' },
            { name: 'Comment', payload: "'; --", desc: '주석 처리' },
            { name: 'Boolean', payload: "' OR 1=1--", desc: '불린 기반' },
            { name: 'Time Delay', payload: "'; WAITFOR DELAY '00:00:05'--", desc: '시간 지연' }
        ];

        return payloads.map(p => `
            <div class="quick-payload-item mb-2">
                <button class="btn btn-sm btn-outline-info w-100 text-start"
                        onclick="SQLInjectionPage.selectPayload('${p.payload.replace(/'/g, "\\'")}')">
                    <strong>${p.name}</strong><br>
                    <small class="text-muted">${p.desc}</small>
                </button>
            </div>
        `).join('');
    },

    renderDocumentation() {
        return `
            <div class="accordion" id="sqlDocumentation">
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button" type="button" data-bs-toggle="collapse"
                                data-bs-target="#attack-types">
                            <i class="fas fa-list-ul me-2"></i> 공격 유형
                        </button>
                    </h2>
                    <div id="attack-types" class="accordion-collapse collapse show">
                        <div class="accordion-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-search"></i> Union-based</h6>
                                    <p>UNION SELECT를 사용하여 데이터베이스에서 데이터를 직접 추출</p>
                                    <code>UNION SELECT username,password FROM users</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-question-circle"></i> Boolean-based</h6>
                                    <p>참/거짓 조건을 통해 데이터를 한 비트씩 추출</p>
                                    <code>AND (SELECT SUBSTR(password,1,1) FROM users LIMIT 1)='a'</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-clock"></i> Time-based</h6>
                                    <p>시간 지연을 이용한 Blind SQL Injection</p>
                                    <code>AND (SELECT SLEEP(5) WHERE username='admin')</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-exclamation-triangle"></i> Error-based</h6>
                                    <p>SQL 오류 메시지를 통해 정보 추출</p>
                                    <code>AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()))))</code>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse"
                                data-bs-target="#prevention">
                            <i class="fas fa-shield-alt me-2"></i> 방어 기법
                        </button>
                    </h2>
                    <div id="prevention" class="accordion-collapse collapse">
                        <div class="accordion-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6><i class="fas fa-code"></i> Prepared Statements</h6>
                                    <p>매개변수화된 쿼리 사용으로 근본적 방어</p>
                                    <code>SELECT * FROM users WHERE id = ?</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-filter"></i> Input Validation</h6>
                                    <p>입력값 검증 및 화이트리스트 필터링</p>
                                    <code>preg_match('/^[a-zA-Z0-9]+$/', $input)</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-user-shield"></i> Least Privilege</h6>
                                    <p>데이터베이스 계정의 최소 권한 부여</p>
                                    <code>GRANT SELECT ON table TO app_user</code>
                                </div>
                                <div class="col-md-6">
                                    <h6><i class="fas fa-quote-right"></i> Escaping</h6>
                                    <p>특수문자 이스케이프 처리 (보조적 방법)</p>
                                    <code>mysqli_real_escape_string($input)</code>
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
        const payloadInput = document.getElementById('sql-payload');
        if (payloadInput) {
            payloadInput.addEventListener('input', (e) => {
                this.sqlPayload = e.target.value;
            });
        }

        // Highlight code syntax
        this.updateCodeHighlighting();

        console.log('✅ SQL Injection page initialized');
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

        // Update current language badge
        const badge = document.querySelector('.badge.bg-info');
        if (badge) {
            badge.textContent = `현재: ${language}`;
        }

        // Update code examples
        this.updateCodeExamples();

        console.log(`✅ Language selected: ${language}`);
    },

    selectPayload(payload) {
        this.sqlPayload = payload;
        const input = document.getElementById('sql-payload');
        if (input) {
            input.value = payload;
        }
        VulnerabilityUtils.showSuccessAlert(`페이로드 선택: ${payload}`);
    },

    loadRandomPayload() {
        const payloads = [
            "' OR '1'='1",
            "' UNION SELECT null,username,password FROM users--",
            "'; DROP TABLE users; --",
            "' OR 1=1--",
            "' UNION SELECT @@version--",
            "' AND (SELECT SLEEP(5))--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a",
            "' UNION SELECT table_name FROM information_schema.tables--"
        ];

        const randomPayload = payloads[Math.floor(Math.random() * payloads.length)];
        this.selectPayload(randomPayload);
    },

    async testVulnerableEndpoint() {
        this.showLoading(true);
        try {
            const serverUrl = this.getCurrentServerUrl();
            const response = await fetch(`${serverUrl}/sql/vulnerable`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: this.sqlPayload })
            });

            if (response.ok) {
                const result = await response.json();
                this.displaySingleResult('vulnerable', result);
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
            const response = await fetch(`${serverUrl}/sql/safe`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload: this.sqlPayload })
            });

            if (response.ok) {
                const result = await response.json();
                this.displaySingleResult('safe', result);
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
            const results = await sqlInjectionModule.executeComparisonTest(serverUrl, this.sqlPayload);
            this.displayComparisonResults(results);
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
                                <div class="bg-dark text-light p-3 rounded font-monospace">
                                    ${result.data ? JSON.stringify(result.data, null, 2) : '결과 없음'}
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>상세 정보</h6>
                                <ul class="list-unstyled">
                                    <li><strong>언어:</strong> ${this.currentLanguage}</li>
                                    <li><strong>페이로드:</strong> <code>${this.sqlPayload}</code></li>
                                    <li><strong>취약점 감지:</strong>
                                        <span class="badge ${result.vulnerability_detected ? 'bg-danger' : 'bg-success'}">
                                            ${result.vulnerability_detected ? '감지됨' : '차단됨'}
                                        </span>
                                    </li>
                                    <li><strong>실행 시간:</strong> ${result.execution_time || 'N/A'}</li>
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
                    <div class="card-header bg-primary text-white">
                        <h5><i class="fas fa-balance-scale"></i> 비교 테스트 결과</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6 class="text-danger"><i class="fas fa-bug"></i> 취약한 코드</h6>
                                <div class="bg-dark text-light p-3 rounded font-monospace mb-3">
                                    ${results.vulnerable ? JSON.stringify(results.vulnerable.data, null, 2) : '테스트 실패'}
                                </div>
                                <div class="alert ${results.vulnerable?.vulnerability_detected ? 'alert-danger' : 'alert-success'}">
                                    ${results.vulnerable?.vulnerability_detected ?
                                        '<i class="fas fa-exclamation-triangle"></i> SQL 주입 성공 - 취약점 확인됨' :
                                        '<i class="fas fa-check"></i> 공격이 차단되었습니다'
                                    }
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6 class="text-success"><i class="fas fa-shield-alt"></i> 보안 코드</h6>
                                <div class="bg-dark text-light p-3 rounded font-monospace mb-3">
                                    ${results.safe ? JSON.stringify(results.safe.data, null, 2) : '테스트 실패'}
                                </div>
                                <div class="alert ${results.safe?.vulnerability_detected ? 'alert-danger' : 'alert-success'}">
                                    ${results.safe?.vulnerability_detected ?
                                        '<i class="fas fa-exclamation-triangle"></i> 보안 코드에서 취약점 감지됨' :
                                        '<i class="fas fa-check"></i> SQL 주입이 성공적으로 차단됨'
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
                                        <li><strong>페이로드:</strong> <code>${this.sqlPayload}</code></li>
                                        <li><strong>취약한 코드:</strong> ${results.vulnerable?.vulnerability_detected ? '취약함' : '안전함'}</li>
                                        <li><strong>보안 코드:</strong> ${results.safe?.vulnerability_detected ? '취약함' : '안전함'}</li>
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
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
        return sqlInjectionModule.getCodeExamples(this.currentLanguage).vulnerable || '// 코드 예시를 불러올 수 없습니다.';
    },

    getSafeCode() {
        return sqlInjectionModule.getCodeExamples(this.currentLanguage).safe || '// 코드 예시를 불러올 수 없습니다.';
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
                try {
                    // Check if required components are loaded
                    if (window.Prism.languages &&
                        (window.Prism.languages.php || window.Prism.languages.sql)) {
                        Prism.highlightAll();
                        VulnerabilityUtils.addCopyButtons();
                        console.log('✅ SQL Injection page syntax highlighting applied');
                    } else {
                        console.warn('⚠️ Prism language components not fully loaded');
                    }
                } catch (error) {
                    console.warn('⚠️ SQL Injection page syntax highlighting failed:', error.message);
                }
            } else {
                console.warn('⚠️ Prism.js not available for SQL Injection page');
            }
        }, 200);
    }
};