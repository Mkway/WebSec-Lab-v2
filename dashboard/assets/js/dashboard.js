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
                    name: 'Basic Script',
                    code: '<script>alert("XSS")</script>'
                },
                {
                    name: 'Image Onerror',
                    code: '<img src=x onerror=alert("XSS")>'
                },
                {
                    name: 'SVG Onload',
                    code: '<svg onload=alert("XSS")>'
                },
                {
                    name: 'Event Handler',
                    code: '" onmouseover="alert(\'XSS\')" "'
                },
                {
                    name: 'Case Bypass',
                    code: '<ScRiPt>alert("XSS")</ScRiPt>'
                },
                {
                    name: 'Iframe Src',
                    code: '<iframe src="javascript:alert(\'XSS\')"></iframe>'
                }
            ]
        };
    },
    mounted() {
        this.checkServerStatus();
        this.loadServerInfo();
        this.setupMessageListener();
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

            // 실행 상태 초기화
            this.xssExecutionStatus = {
                vulnerable: null,
                safe: null
            };

            try {
                const payload = {
                    payload: this.xssPayload,
                    mode: this.xssMode,
                    context: {
                        scenario: this.xssScenario
                    }
                };

                console.log('🚀 Sending XSS test request:', payload);
                console.log('🌐 Target URL:', '/api/vulnerabilities/xss');

                const response = await fetch('/api/vulnerabilities/xss', {
                    method: 'POST',
                    mode: 'cors',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify(payload)
                });

                console.log('📡 Response status:', response.status);
                console.log('📡 Response headers:', Object.fromEntries(response.headers.entries()));

                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }

                const data = await response.json();
                console.log('✅ XSS test response:', data);

                this.xssResult = {
                    success: true,
                    data: data
                };

                // 성공 알림
                this.showSuccessAlert('XSS 테스트가 성공적으로 완료되었습니다!');

            } catch (error) {
                console.error('❌ XSS test failed:', error);

                this.xssResult = {
                    success: false,
                    error: error.message,
                    details: error.toString()
                };

                // 에러 알림
                this.showErrorAlert(`테스트 실행 실패: ${error.message}`);
            } finally {
                this.isLoading = false;
            }
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
            alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            alertDiv.innerHTML = `
                <i class="fas fa-check-circle"></i>
                <strong>성공!</strong><br>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 3000);
        },
        showErrorAlert(message) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-danger alert-dismissible fade show position-fixed';
            alertDiv.style.cssText = 'top: 20px; right: 20px; z-index: 9999; min-width: 300px;';
            alertDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <strong>오류!</strong><br>
                ${message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            document.body.appendChild(alertDiv);

            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.parentNode.removeChild(alertDiv);
                }
            }, 5000);
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