const { createApp } = Vue;

// Import modular components
import { languageServers, vulnerabilityCategories } from './config/servers.js?v=5';
import { VulnerabilityUtils } from './vulnerabilities/common.js?v=5';
import { xssModule } from './vulnerabilities/xss.js?v=8';
import { componentLoader } from './component-loader.js?v=1';

createApp({
    data() {
        return {
            serverStatus: 'Connected',
            phpStatus: 'Running',
            activeVuln: null, // 초기값을 null로 설정
            selectedLanguage: 'PHP',
            isLoading: false,

            // 언어별 서버 정보 (모듈에서 가져옴)
            languageServers: languageServers,
            // 카테고리별 그룹화된 취약점 목록 (모듈에서 가져옴)
            vulnerabilityCategories: vulnerabilityCategories,

            // 현재 활성화된 카테고리
            activeCategory: 'injection-attacks',

            // 개별 취약점 호환성을 위한 플랫 리스트
            vulnerabilities: [],
            xssPayload: '&lt;script&gt;alert("XSS")&lt;/script&gt;',
            xssMode: 'both',
            xssScenario: 'basic',
            xssResult: null,
            xssExecutionStatus: {
                vulnerable: null,
                safe: null
            },

            // SQL Injection 관련 데이터
            sqlUsername: "admin' OR '1'='1",
            sqlPassword: "' OR '1'='1",
            sqlTestBoth: true,
            sqlResult: null,

            quickPayloads: [
                {
                    name: '기본 스크립트',
                    icon: '🚀',
                    code: '&lt;script&gt;alert("XSS")&lt;/script&gt;',
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

            // SQL Injection 페이로드
            sqlPayloads: [
                {
                    name: '기본 우회',
                    icon: '🔓',
                    username: "admin' OR '1'='1",
                    password: "' OR '1'='1",
                    description: '가장 기본적인 인증 우회 공격입니다'
                },
                {
                    name: '주석 우회',
                    icon: '💬',
                    username: "admin'--",
                    password: "anything",
                    description: 'SQL 주석을 이용한 우회 공격입니다'
                },
                {
                    name: 'UNION 공격',
                    icon: '🔗',
                    username: "' UNION SELECT user(),version()--",
                    password: "anything",
                    description: 'UNION을 이용한 데이터베이스 정보 추출입니다'
                },
                {
                    name: '시간 지연',
                    icon: '⏰',
                    username: "admin'; WAITFOR DELAY '00:00:05'--",
                    password: "anything",
                    description: '시간 지연을 이용한 블라인드 SQL 인젝션입니다'
                },
                {
                    name: '오류 기반',
                    icon: '❌',
                    username: "admin' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    password: "anything",
                    description: 'SQL 오류를 이용한 정보 추출입니다'
                },
                {
                    name: 'NoSQL 우회',
                    icon: '🍃',
                    username: 'admin" || "1"=="1',
                    password: 'anything',
                    description: 'MongoDB 등 NoSQL 데이터베이스 우회입니다'
                }
            ],
            testProgress: {
                show: false,
                percentage: 0
            },
            liveTestResult: null
        };
    },
    async mounted() {
        await this.initializeApp();
    },
    methods: {
        async initializeApp() {
            this.initializeVulnerabilities();
            this.checkServerStatus();
            this.checkAllLanguageServers();
            this.loadServerInfo();
            this.setupMessageListener();
            this.initializePrism();

            // 컴포넌트 프리로드
            await componentLoader.preloadComponents(['main-dashboard', 'xss-test', 'sql-injection-test']);

            // 메인 대시보드 로드
            await this.showMainDashboard();

            // 컴포넌트 로드 이벤트 리스너
            document.addEventListener('componentLoaded', (e) => {
                const { componentName } = e.detail;
                if (componentName === 'xss-test') {
                    xssModule.initializeEventHandlers();
                }
                this.updateCodeHighlighting();
            });

            // 초기 코드 하이라이팅 실행
            setTimeout(() => {
                this.updateCodeHighlighting();
            }, 500);
        },

        initializeVulnerabilities() {
            // 카테고리별 취약점을 플랫 리스트로 변환
            this.vulnerabilities = [];
            this.vulnerabilityCategories.forEach(category => {
                this.vulnerabilities.push(...category.vulnerabilities);
            });
        },

        async selectVulnerability(type) {
            this.activeVuln = type;
            this.xssResult = null;
            this.sqlResult = null;

            let componentName = '';
            switch (type) {
                case 'xss':
                    componentName = 'xss-test';
                    break;
                case 'sql-injection':
                    componentName = 'sql-injection-test';
                    break;
                default:
                    await this.showMainDashboard();
                    return;
            }

            const success = await componentLoader.renderComponent(componentName);
            if (success) {
                console.log(`✅ ${type} component loaded successfully`);
            }
        },

        async showMainDashboard() {
            this.activeVuln = null;
            await componentLoader.renderMainDashboard();
        },

        // 언어 선택 기능
        selectLanguage(language) {
            this.selectedLanguage = language;
        },

        // 서버 상태 확인
        checkServerStatus() {
            // 실제 서버 상태 확인 로직
            this.serverStatus = 'Connected';
        },

        // 모든 언어 서버 상태 확인
        async checkAllLanguageServers() {
            for (const [language, server] of Object.entries(this.languageServers)) {
                try {
                    const response = await fetch(`http://localhost:${server.port}/health`, {
                        method: 'GET',
                        timeout: 2000
                    });

                    if (response.ok) {
                        server.status = 'running';
                        console.log(`✅ Server ${language}: running`);
                    } else {
                        server.status = 'error';
                        console.log(`❌ Server ${language} health check failed: ${response.status}`);
                    }
                } catch (error) {
                    server.status = 'offline';
                    console.log(`❌ Server ${language} health check failed: ${error.message}`);
                }
            }
        },

        async loadServerInfo() {
            try {
                const response = await fetch('http://localhost:8080/api/health');
                if (response.ok) {
                    const data = await response.json();
                    console.log('Server info loaded:', data);
                }
            } catch (error) {
                console.log('Server info load failed:', error);
            }
        },

        setupMessageListener() {
            // 메시지 수신 설정
        },

        initializePrism() {
            if (typeof Prism !== 'undefined') {
                Prism.highlightAll();
            }
        },

        updateCodeHighlighting() {
            console.log('🎨 Updating code highlighting...');
            console.log('Prism available:', typeof Prism !== 'undefined');

            if (typeof Prism !== 'undefined') {
                setTimeout(() => {
                    const codeBlocks = document.querySelectorAll('pre code');
                    console.log('Code blocks found:', codeBlocks.length);

                    if (codeBlocks.length > 0) {
                        console.log('Available Prism languages:', Object.keys(Prism.languages));
                        Prism.highlightAll();
                    }
                    console.log('✅ Code highlighting completed');
                }, 100);
            }
        },

        // XSS 관련 메서드들
        loadSamplePayload() {
            this.xssPayload = '&lt;script&gt;alert("XSS")&lt;/script&gt;';
            this.showSuccessAlert('🎯 샘플 XSS 페이로드가 로드되었습니다!');
        },

        applyQuickPayload(payload) {
            this.xssPayload = payload.code;
            this.showSuccessAlert(`🎯 ${payload.name} 페이로드가 적용되었습니다!`);
        },

        async executeXSSTest() {
            return await xssModule.executeTest(this.xssPayload, this.selectedLanguage);
        },

        // SQL 관련 메서드들
        loadSqlSample() {
            this.sqlUsername = "admin' OR '1'='1";
            this.sqlPassword = "' OR '1'='1";
            this.showSuccessAlert('🎯 기본 SQL 인젝션 페이로드가 로드되었습니다!');
        },

        applySqlPayload(payload) {
            this.sqlUsername = payload.username;
            this.sqlPassword = payload.password;
            this.showSuccessAlert(`🎯 ${payload.name} 페이로드가 적용되었습니다!`);
        },

        async executeSQLTest() {
            if (!this.sqlUsername.trim()) {
                this.showErrorAlert('사용자명을 입력해주세요!');
                return;
            }

            const server = this.languageServers[this.selectedLanguage];
            if (!server || server.status !== 'running') {
                this.showErrorAlert(`${this.selectedLanguage} 서버가 실행되지 않았습니다!`);
                return;
            }

            this.isLoading = true;
            this.sqlResult = null;

            try {
                let results = [];

                if (this.sqlTestBoth) {
                    // 취약한 버전과 안전한 버전 모두 테스트
                    const vulnerableResult = await this.testSQL('vulnerable');
                    const safeResult = await this.testSQL('safe');
                    results = [vulnerableResult, safeResult];
                } else {
                    // 취약한 버전만 테스트
                    const result = await this.testSQL('vulnerable');
                    results = [result];
                }

                this.displaySQLResults(results);
                this.showSuccessAlert('🎯 SQL 인젝션 테스트가 완료되었습니다!');

            } catch (error) {
                console.error('SQL test error:', error);
                this.showErrorAlert(`테스트 중 오류가 발생했습니다: ${error.message}`);
            } finally {
                this.isLoading = false;
            }
        },

        async testSQL(mode) {
            const server = this.languageServers[this.selectedLanguage];
            const serverUrl = `http://localhost:${server.port}`;
            const endpoint = `/vulnerabilities/sql-injection`;

            const requestData = {
                payload: this.sqlUsername,
                target: 'login',
                mode: mode,
                username: this.sqlUsername,
                password: this.sqlPassword
            };

            console.log(`🔍 Testing ${this.selectedLanguage} SQL Injection (${mode}):`, requestData);

            const response = await fetch(`${serverUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();

            return {
                language: this.selectedLanguage,
                mode: mode,
                success: response.ok,
                data: data,
                status: response.status
            };
        },

        displaySQLResults(results) {
            let html = '';

            results.forEach(result => {
                const modeClass = result.mode === 'vulnerable' ? 'border-danger' : 'border-success';
                const modeIcon = result.mode === 'vulnerable' ? 'fas fa-exclamation-triangle text-danger' : 'fas fa-shield-alt text-success';
                const modeBadge = result.mode === 'vulnerable' ?
                    '<span class="badge bg-danger"><i class="fas fa-bug"></i> 취약한 코드</span>' :
                    '<span class="badge bg-success"><i class="fas fa-shield-alt"></i> 안전한 코드</span>';

                const server = this.languageServers[result.language];
                const attackSuccess = result.data?.result?.authentication_bypassed ||
                                    result.data?.data?.attack_success ||
                                    result.data?.success === true;

                html += `
                    <div class="card mb-3 ${modeClass}">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <div>
                                <h6 class="mb-0">
                                    <i class="${modeIcon}"></i>
                                    ${server.icon} ${result.language} - ${result.mode === 'vulnerable' ? '취약한 코드' : '안전한 코드'}
                                </h6>
                            </div>
                            <div>
                                ${modeBadge}
                                ${attackSuccess ? '<span class="badge bg-warning ms-1"><i class="fas fa-exclamation"></i> 공격 성공</span>' : ''}
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-8">
                                    <strong>📊 실행 결과:</strong>
                                    <div class="bg-light p-3 rounded mt-2">
                                        <pre class="mb-0"><code>${JSON.stringify(result.data, null, 2)}</code></pre>
                                    </div>
                                </div>
                                <div class="col-md-4">
                                    <strong>🔍 테스트 정보:</strong>
                                    <div class="mt-2">
                                        <div class="mb-2">
                                            <small class="text-muted">사용자명:</small><br>
                                            <code class="bg-light px-2 py-1 rounded">${this.sqlUsername}</code>
                                        </div>
                                        <div class="mb-2">
                                            <small class="text-muted">비밀번호:</small><br>
                                            <code class="bg-light px-2 py-1 rounded">${this.sqlPassword}</code>
                                        </div>
                                        <div>
                                            <small class="text-muted">응답 코드:</small><br>
                                            <span class="badge ${result.status === 200 ? 'bg-success' : 'bg-warning'}">${result.status}</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            });

            this.sqlResult = html;
        },

        // 기타 유틸리티 메서드
        getVulnName(type) {
            const vuln = this.vulnerabilities.find(v => v.type === type);
            return vuln ? vuln.name : '알 수 없는 취약점';
        },

        showSuccessAlert(message) {
            VulnerabilityUtils.showSuccessAlert(message);
        },

        showErrorAlert(message) {
            VulnerabilityUtils.showErrorAlert(message);
        }
    }
}).mount('#app');