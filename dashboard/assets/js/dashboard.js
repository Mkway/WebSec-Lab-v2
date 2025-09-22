const { createApp } = Vue;

createApp({
    data() {
        return {
            serverStatus: 'Connected',
            phpStatus: 'Running',
            activeVuln: 'xss',
            isLoading: false,
            vulnerabilities: [
                {
                    type: 'xss',
                    name: 'XSS',
                    icon: 'fas fa-code',
                    status: 'completed'
                },
                {
                    type: 'sql-injection',
                    name: 'SQL Injection',
                    icon: 'fas fa-database',
                    status: 'completed'
                },
                {
                    type: 'command-injection',
                    name: 'Command Injection',
                    icon: 'fas fa-terminal',
                    status: 'progress'
                },
                {
                    type: 'file-upload',
                    name: 'File Upload',
                    icon: 'fas fa-upload',
                    status: 'planned'
                },
                {
                    type: 'directory-traversal',
                    name: 'Directory Traversal',
                    icon: 'fas fa-folder-open',
                    status: 'planned'
                },
                {
                    type: 'object-injection',
                    name: 'Object Injection',
                    icon: 'fas fa-syringe',
                    status: 'planned'
                }
            ],
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
                currentStep: 'request',
                steps: ['request', 'parse', 'execute', 'analyze', 'result']
            }
        };
    },
    mounted() {
        this.checkServerStatus();
        this.loadServerInfo();
        this.setupMessageListener();
        this.initializePrism();
    },
    methods: {
        selectVulnerability(type) {
            this.activeVuln = type;
            this.xssResult = null;
        },
        getVulnName(type) {
            const vuln = this.vulnerabilities.find(v => v.type === type);
            return vuln ? vuln.name : 'Unknown';
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
                // Step 1: 요청 전송
                this.updateProgressStep('request');
                await this.delay(800);

                const payload = {
                    payload: this.xssPayload,
                    mode: this.xssMode,
                    context: {
                        scenario: this.xssScenario
                    }
                };

                console.log('🚀 Sending XSS test request:', payload);

                // Step 2: 코드 파싱
                this.updateProgressStep('parse');
                await this.delay(600);

                const response = await fetch('/api/vulnerabilities/xss', {
                    method: 'POST',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                // Step 3: 코드 실행
                this.updateProgressStep('execute');
                await this.delay(1000);

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                // Step 4: 보안 분석
                this.updateProgressStep('analyze');
                await this.delay(800);

                const data = await response.json();
                console.log('✅ XSS test response:', data);

                // Step 5: 결과 생성
                this.updateProgressStep('result');
                await this.delay(500);

                this.xssResult = {
                    success: true,
                    data: data
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