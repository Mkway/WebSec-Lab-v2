// Navigation Component
import { vulnerabilityCategories } from '../config/servers.js?v=6';

export const NavigationComponent = {
    render() {
        return `
            <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
                <div class="container-fluid">
                    <!-- Brand -->
                    <a class="navbar-brand" href="#" onclick="router.navigate('dashboard')" data-route="dashboard">
                        <i class="fas fa-shield-alt"></i> WebSec-Lab v2
                    </a>

                    <!-- Mobile Toggle -->
                    <button class="navbar-toggler" type="button" data-bs-toggle="collapse"
                            data-bs-target="#navbarNav" aria-controls="navbarNav"
                            aria-expanded="false" aria-label="Toggle navigation">
                        <span class="navbar-toggler-icon"></span>
                    </button>

                    <!-- Navigation Items -->
                    <div class="collapse navbar-collapse" id="navbarNav">
                        <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                            <!-- Dashboard -->
                            <li class="nav-item">
                                <a class="nav-link" href="#" onclick="router.navigate('dashboard')"
                                   data-route="dashboard">
                                    <i class="fas fa-home"></i> 대시보드
                                </a>
                            </li>

                            <!-- Vulnerability Dropdown -->
                            <li class="nav-item dropdown">
                                <a class="nav-link dropdown-toggle" href="#" role="button"
                                   data-bs-toggle="dropdown" aria-expanded="false">
                                    <i class="fas fa-bug"></i> 취약점 테스트
                                </a>
                                <ul class="dropdown-menu">
                                    ${this.renderVulnerabilityDropdown()}
                                </ul>
                            </li>

                            <!-- Tools -->
                            <li class="nav-item">
                                <a class="nav-link" href="#" onclick="router.navigate('tools')"
                                   data-route="tools">
                                    <i class="fas fa-tools"></i> 보안 도구
                                </a>
                            </li>

                            <!-- Documentation -->
                            <li class="nav-item">
                                <a class="nav-link" href="#" onclick="router.navigate('docs')"
                                   data-route="docs">
                                    <i class="fas fa-book"></i> 문서
                                </a>
                            </li>
                        </ul>

                        <!-- Right Side Items -->
                        <ul class="navbar-nav">
                            <!-- Server Status -->
                            <li class="nav-item dropdown">
                                <a class="nav-link dropdown-toggle" href="#" role="button"
                                   data-bs-toggle="dropdown" aria-expanded="false" id="server-status-indicator">
                                    <i class="fas fa-circle text-warning animate-pulse"></i> 서버 확인중
                                </a>
                                <ul class="dropdown-menu dropdown-menu-end">
                                    <li><h6 class="dropdown-header">서버 상태</h6></li>
                                    <li id="php-server-status">
                                        <span class="dropdown-item">
                                            <i class="fas fa-spinner fa-spin text-muted me-2"></i>PHP Server
                                            <span class="badge bg-secondary ms-auto">확인중</span>
                                        </span>
                                    </li>
                                    <li id="nodejs-server-status">
                                        <span class="dropdown-item">
                                            <i class="fas fa-spinner fa-spin text-muted me-2"></i>Node.js Server
                                            <span class="badge bg-secondary ms-auto">확인중</span>
                                        </span>
                                    </li>
                                    <li id="python-server-status">
                                        <span class="dropdown-item">
                                            <i class="fas fa-spinner fa-spin text-muted me-2"></i>Python Server
                                            <span class="badge bg-secondary ms-auto">확인중</span>
                                        </span>
                                    </li>
                                    <li id="java-server-status">
                                        <span class="dropdown-item">
                                            <i class="fas fa-spinner fa-spin text-muted me-2"></i>Java Server
                                            <span class="badge bg-secondary ms-auto">확인중</span>
                                        </span>
                                    </li>
                                    <li id="go-server-status">
                                        <span class="dropdown-item">
                                            <i class="fas fa-spinner fa-spin text-muted me-2"></i>Go Server
                                            <span class="badge bg-secondary ms-auto">확인중</span>
                                        </span>
                                    </li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li>
                                        <span class="dropdown-item">
                                            <button class="btn btn-sm btn-outline-primary w-100" onclick="NavigationComponent.checkAllServers()">
                                                <i class="fas fa-sync-alt"></i> 상태 새로고침
                                            </button>
                                        </span>
                                    </li>
                                </ul>
                            </li>

                            <!-- Settings -->
                            <li class="nav-item dropdown">
                                <a class="nav-link dropdown-toggle" href="#" role="button"
                                   data-bs-toggle="dropdown" aria-expanded="false">
                                    <i class="fas fa-cog"></i>
                                </a>
                                <ul class="dropdown-menu dropdown-menu-end">
                                    <li>
                                        <a class="dropdown-item" href="#" onclick="router.navigate('settings')">
                                            <i class="fas fa-cog"></i> 설정
                                        </a>
                                    </li>
                                    <li>
                                        <a class="dropdown-item" href="#" onclick="NavigationComponent.toggleTheme()">
                                            <i class="fas fa-moon"></i> 다크 모드
                                        </a>
                                    </li>
                                    <li><hr class="dropdown-divider"></li>
                                    <li>
                                        <a class="dropdown-item" href="#" onclick="router.navigate('about')">
                                            <i class="fas fa-info-circle"></i> 정보
                                        </a>
                                    </li>
                                </ul>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>
        `;
    },

    renderVulnerabilityDropdown() {
        let html = '';

        vulnerabilityCategories.forEach(category => {
            // Category header
            html += `<li><h6 class="dropdown-header">${category.name}</h6></li>`;

            // Category vulnerabilities
            category.vulnerabilities.forEach(vuln => {
                if (vuln.status === 'completed') {
                    html += `
                        <li>
                            <a class="dropdown-item" href="#" onclick="console.log('Navigating to: vulnerability/${vuln.type}'); router.navigate('vulnerability/${vuln.type}'); return false;"
                               data-route="vulnerability/${vuln.type}">
                                <i class="${vuln.icon} me-2"></i>${vuln.name}
                                <span class="badge bg-success ms-2">활성</span>
                            </a>
                        </li>
                    `;
                } else {
                    html += `
                        <li>
                            <span class="dropdown-item text-muted">
                                <i class="${vuln.icon} me-2"></i>${vuln.name}
                                <span class="badge bg-secondary ms-2">준비중</span>
                            </span>
                        </li>
                    `;
                }
            });

            html += `<li><hr class="dropdown-divider"></li>`;
        });

        return html;
    },

    // Initialize navigation
    initialize() {
        // Update navigation on route changes
        window.addEventListener('route-changed', (event) => {
            this.updateActiveNavigation(event.detail.path);
        });

        // Set up server status monitoring
        this.setupServerStatusMonitoring();

        console.log('✅ Navigation component initialized');
    },

    // Update active navigation state
    updateActiveNavigation(currentPath) {
        // Remove active class from all nav items
        document.querySelectorAll('.nav-link[data-route]').forEach(link => {
            link.classList.remove('active');
        });

        document.querySelectorAll('.dropdown-item[data-route]').forEach(link => {
            link.classList.remove('active');
        });

        // Add active class to current route
        const activeNavLink = document.querySelector(`[data-route="${currentPath}"]`);
        if (activeNavLink) {
            activeNavLink.classList.add('active');
        }

        // Handle vulnerability routes
        if (currentPath.startsWith('vulnerability/')) {
            const vulnDropdown = document.querySelector('.nav-link.dropdown-toggle');
            if (vulnDropdown) {
                vulnDropdown.classList.add('active');
            }
        }
    },

    // Setup server status monitoring
    setupServerStatusMonitoring() {
        // Initial check
        this.checkAllServers();

        // Check every 30 seconds
        setInterval(() => {
            this.checkAllServers();
        }, 30000);
    },

    // Check all servers and update UI
    async checkAllServers() {
        const servers = [
            { name: 'PHP', key: 'php', port: 8080, icon: '🐘' },
            { name: 'Node.js', key: 'nodejs', port: 3000, icon: '💚' },
            { name: 'Python', key: 'python', port: 5000, icon: '🐍' },
            { name: 'Java', key: 'java', port: 8081, icon: '☕' },
            { name: 'Go', key: 'go', port: 8082, icon: '🐹' }
        ];

        let onlineCount = 0;
        const totalCount = servers.length;

        // Check each server
        for (const server of servers) {
            const isOnline = await this.checkSingleServer(server);
            if (isOnline) onlineCount++;
        }

        // Update main status indicator
        this.updateMainStatusIndicator(onlineCount, totalCount);
    },

    // Check single server status
    async checkSingleServer(server) {
        const statusElement = document.getElementById(`${server.key}-server-status`);
        if (!statusElement) return false;

        try {
            // Show loading state
            statusElement.innerHTML = `
                <span class="dropdown-item">
                    <i class="fas fa-spinner fa-spin text-muted me-2"></i>${server.icon} ${server.name}
                    <span class="badge bg-secondary ms-auto">확인중</span>
                </span>
            `;

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(`http://localhost:${server.port}/health`, {
                method: 'GET',
                mode: 'cors',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                // Server is online
                statusElement.innerHTML = `
                    <span class="dropdown-item">
                        <i class="fas fa-circle text-success me-2"></i>${server.icon} ${server.name}
                        <span class="badge bg-success ms-auto">온라인</span>
                    </span>
                `;
                return true;
            } else {
                throw new Error(`HTTP ${response.status}`);
            }

        } catch (error) {
            // Server is offline
            statusElement.innerHTML = `
                <span class="dropdown-item">
                    <i class="fas fa-circle text-danger me-2"></i>${server.icon} ${server.name}
                    <span class="badge bg-danger ms-auto">오프라인</span>
                </span>
            `;
            console.warn(`${server.name} server is offline:`, error.message);
            return false;
        }
    },

    // Update main status indicator
    updateMainStatusIndicator(onlineCount, totalCount) {
        const statusIndicator = document.getElementById('server-status-indicator');
        if (!statusIndicator) return;

        if (onlineCount === totalCount) {
            statusIndicator.innerHTML = '<i class="fas fa-circle text-success"></i> 모든 서버 온라인';
            statusIndicator.className = 'nav-link dropdown-toggle text-success';
        } else if (onlineCount > 0) {
            statusIndicator.innerHTML = `<i class="fas fa-circle text-warning"></i> ${onlineCount}/${totalCount} 서버 온라인`;
            statusIndicator.className = 'nav-link dropdown-toggle text-warning';
        } else {
            statusIndicator.innerHTML = '<i class="fas fa-circle text-danger"></i> 서버 오프라인';
            statusIndicator.className = 'nav-link dropdown-toggle text-danger';
        }

        console.log(`📊 Server status: ${onlineCount}/${totalCount} online`);
    },

    // Toggle theme
    toggleTheme() {
        const body = document.body;
        const currentTheme = body.getAttribute('data-theme');

        if (currentTheme === 'dark') {
            body.setAttribute('data-theme', 'light');
            localStorage.setItem('theme', 'light');
        } else {
            body.setAttribute('data-theme', 'dark');
            localStorage.setItem('theme', 'dark');
        }

        // Show theme changed notification
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-info alert-dismissible fade show position-fixed';
        alertDiv.style.cssText = 'top: 80px; right: 20px; z-index: 9999; min-width: 250px;';
        alertDiv.innerHTML = `
            <i class="fas fa-palette"></i> 테마가 변경되었습니다
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.body.appendChild(alertDiv);

        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.parentNode.removeChild(alertDiv);
            }
        }, 3000);
    },

    // Load saved theme
    loadTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme) {
            document.body.setAttribute('data-theme', savedTheme);
        }
    }
};