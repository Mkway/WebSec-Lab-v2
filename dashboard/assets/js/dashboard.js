const { createApp } = Vue;

// Import modular components
import { languageServers, vulnerabilityCategories } from './config/servers.js?v=5';
import { VulnerabilityUtils } from './vulnerabilities/common.js?v=5';
import { xssModule } from './vulnerabilities/xss.js?v=8';
import { sqlInjectionModule } from './vulnerabilities/sql-injection.js?v=8';

createApp({
    data() {
        return {
            serverStatus: 'Connected',
            phpStatus: 'Running',
            activeVuln: 'sql-injection',
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

        // 초기 코드 하이라이팅 실행
        setTimeout(() => {
            this.updateCodeHighlighting();
        }, 500);
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

            // 다음 틱에서 취약점 모듈 초기화 및 UI 렌더링
            this.$nextTick(() => {
                this.initializeVulnerabilityModule(type);
                this.renderVulnerabilityUI(type);
            });
        },

        // 언어 선택 기능
        selectLanguage(language) {
            this.selectedLanguage = language;
            this.xssResult = null;
            console.log(`✅ Selected language: ${language}`);

            // 언어 변경 후 코드 하이라이팅 재실행
            setTimeout(() => {
                this.updateCodeHighlighting();
            }, 100);
        },

        // 언어별 Prism.js 클래스 매핑 (공통 모듈 사용)
        getLanguageClass(language) {
            return VulnerabilityUtils.getLanguageClass(language);
        },

        // XSS 코드 예시 가져오기
        getXSSCodeExamples(language) {
            return xssModule.getCodeExamples(language);
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
                await VulnerabilityUtils.checkServerStatus(language, server);
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
                '&lt;script&gt;alert("XSS Test")&lt;/script&gt;',
                '<img src=x onerror=alert("IMG XSS")>',
                '<svg onload=alert("SVG XSS")>',
                '">&lt;script&gt;alert("Attribute XSS")&lt;/script&gt;',
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
            return VulnerabilityUtils.delay(ms);
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
            VulnerabilityUtils.addCopyButtons();
        },

        copyCodeToClipboard(text) {
            VulnerabilityUtils.copyCodeToClipboard(text);
        },

        updateCodeHighlighting() {
            // Vue의 반응성을 위해 nextTick 사용
            this.$nextTick(() => {
                console.log('🎨 Updating code highlighting...');
                console.log('Prism available:', !!window.Prism);
                console.log('Code blocks found:', document.querySelectorAll('pre code').length);

                if (window.Prism) {
                    // 모든 언어 컴포넌트가 로드되었는지 확인
                    console.log('Available Prism languages:', Object.keys(Prism.languages));

                    // 강제로 모든 코드 블록 다시 하이라이트
                    document.querySelectorAll('pre code').forEach(block => {
                        Prism.highlightElement(block);
                    });

                    // 복사 버튼 추가
                    VulnerabilityUtils.addCopyButtons();

                    console.log('✅ Code highlighting completed');
                } else {
                    console.error('❌ Prism.js not available');
                }
            });
        },
        getRiskClass(level) {
            return VulnerabilityUtils.getRiskClass(level);
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
            VulnerabilityUtils.showSuccessAlert(message);
        },
        showErrorAlert(message) {
            VulnerabilityUtils.showErrorAlert(message);
        },
        // Vulnerability-specific methods
        renderVulnerabilityInterface(type) {
            switch(type) {
                case 'xss':
                    return xssModule.renderInterface();
                case 'sql-injection':
                    return sqlInjectionModule.renderInterface();
                default:
                    return '<div class="alert alert-info">해당 취약점은 아직 구현되지 않았습니다.</div>';
            }
        },

        initializeVulnerabilityModule(type) {
            switch(type) {
                case 'xss':
                    xssModule.initializeEventHandlers();
                    break;
                case 'sql-injection':
                    sqlInjectionModule.initializeEventHandlers();
                    break;
            }
        },

        // 취약점 UI 직접 렌더링 (v-html 대신 사용)
        renderVulnerabilityUI(type) {
            if (type === 'sql-injection') {
                const container = document.getElementById('sql-injection-container');
                if (container) {
                    const html = this.renderVulnerabilityInterface(type);
                    container.innerHTML = html;
                    console.log('✅ SQL Injection UI rendered successfully');

                    // 이벤트 핸들러 재초기화
                    setTimeout(() => {
                        sqlInjectionModule.initializeEventHandlers();
                    }, 100);
                }
            }
        },

        // Utility methods for future vulnerability types
        async executeSQLTest() {
            // Delegate to SQL injection module
            return await sqlInjectionModule.executeSQLTest();
        },
        async executeCommandTest() {
            // TODO: Implement command injection testing
            console.log('Command injection test not implemented yet');
        }
    }
}).mount('#app');