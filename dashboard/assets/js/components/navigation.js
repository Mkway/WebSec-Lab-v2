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
                            <li class="nav-item">
                                <span class="nav-link" id="server-status-indicator">
                                    <i class="fas fa-circle text-success"></i> 서버 연결됨
                                </span>
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
        const statusIndicator = document.getElementById('server-status-indicator');
        if (!statusIndicator) return;

        // Check server status periodically
        const checkStatus = async () => {
            let totalServers = 0;
            let onlineServers = 0;

            const servers = [
                { name: 'PHP', port: 8080 },
                { name: 'Node.js', port: 3000 },
                { name: 'Python', port: 5000 },
                { name: 'Java', port: 8081 },
                { name: 'Go', port: 8082 }
            ];

            for (const server of servers) {
                totalServers++;
                try {
                    const response = await fetch(`http://localhost:${server.port}/health`, {
                        method: 'GET',
                        mode: 'cors',
                        signal: AbortSignal.timeout(3000)
                    });

                    if (response.ok) {
                        onlineServers++;
                    }
                } catch (error) {
                    // Server is offline
                }
            }

            // Update status indicator
            if (onlineServers === totalServers) {
                statusIndicator.innerHTML = '<i class="fas fa-circle text-success"></i> 모든 서버 온라인';
                statusIndicator.className = 'nav-link text-success';
            } else if (onlineServers > 0) {
                statusIndicator.innerHTML = `<i class="fas fa-circle text-warning"></i> ${onlineServers}/${totalServers} 서버 온라인`;
                statusIndicator.className = 'nav-link text-warning';
            } else {
                statusIndicator.innerHTML = '<i class="fas fa-circle text-danger"></i> 서버 오프라인';
                statusIndicator.className = 'nav-link text-danger';
            }
        };

        // Initial check
        checkStatus();

        // Check every 30 seconds
        setInterval(checkStatus, 30000);
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