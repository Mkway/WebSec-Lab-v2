// Main Dashboard Page Component
import { languageServers, vulnerabilityCategories } from '../config/servers.js?v=6';
import { VulnerabilityUtils } from '../vulnerabilities/common.js?v=6';

export const DashboardPage = {
    async render() {
        return `
            <div class="dashboard-main">
                <!-- Header Section -->
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="card bg-gradient-primary text-white">
                            <div class="card-body text-center py-5">
                                <h1 class="display-4 mb-3">
                                    <i class="fas fa-shield-alt"></i>
                                    WebSec-Lab v2
                                </h1>
                                <p class="lead mb-4">실전 웹 보안 취약점 학습 및 모의 침투 테스트 플랫폼</p>
                                <div class="row justify-content-center">
                                    <div class="col-auto">
                                        <div class="d-flex align-items-center gap-3">
                                            <span class="badge bg-light text-dark fs-6">
                                                <i class="fas fa-code"></i> 다중 언어 지원
                                            </span>
                                            <span class="badge bg-light text-dark fs-6">
                                                <i class="fas fa-bug"></i> 실전 취약점
                                            </span>
                                            <span class="badge bg-light text-dark fs-6">
                                                <i class="fas fa-rocket"></i> 실시간 테스트
                                            </span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Language Servers Status -->
                <div class="row mb-4">
                    <div class="col-12">
                        <h3><i class="fas fa-server"></i> 언어별 서버 상태</h3>
                        <div class="row" id="server-status-cards">
                            ${this.renderServerCards()}
                        </div>
                    </div>
                </div>

                <!-- Vulnerability Categories -->
                <div class="row">
                    <div class="col-12">
                        <h3><i class="fas fa-bug"></i> 취약점 카테고리</h3>
                        <div class="row" id="vulnerability-categories">
                            ${this.renderVulnerabilityCategories()}
                        </div>
                    </div>
                </div>

                <!-- Quick Actions -->
                <div class="row mt-4">
                    <div class="col-12">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-bolt"></i> 빠른 실행</h5>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-md-6 col-lg-3 mb-3">
                                        <button class="btn btn-primary w-100 h-100 d-flex flex-column align-items-center justify-content-center p-3"
                                                onclick="router.navigate('vulnerability/sql-injection')">
                                            <i class="fas fa-database fa-2x mb-2"></i>
                                            <span>SQL Injection</span>
                                            <small class="text-white-50">데이터베이스 공격</small>
                                        </button>
                                    </div>
                                    <div class="col-md-6 col-lg-3 mb-3">
                                        <button class="btn btn-warning w-100 h-100 d-flex flex-column align-items-center justify-content-center p-3"
                                                onclick="router.navigate('vulnerability/xss')">
                                            <i class="fas fa-code fa-2x mb-2"></i>
                                            <span>Cross-Site Scripting</span>
                                            <small class="text-dark">스크립트 주입</small>
                                        </button>
                                    </div>
                                    <div class="col-md-6 col-lg-3 mb-3">
                                        <button class="btn btn-info w-100 h-100 d-flex flex-column align-items-center justify-content-center p-3"
                                                onclick="router.navigate('vulnerability/command-injection')">
                                            <i class="fas fa-terminal fa-2x mb-2"></i>
                                            <span>Command Injection</span>
                                            <small class="text-white-50">명령어 주입</small>
                                        </button>
                                    </div>
                                    <div class="col-md-6 col-lg-3 mb-3">
                                        <button class="btn btn-secondary w-100 h-100 d-flex flex-column align-items-center justify-content-center p-3"
                                                onclick="router.navigate('tools')">
                                            <i class="fas fa-tools fa-2x mb-2"></i>
                                            <span>보안 도구</span>
                                            <small class="text-white-50">분석 도구</small>
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    },

    renderServerCards() {
        return Object.entries(languageServers).map(([name, server]) => `
            <div class="col-md-6 col-lg-4 col-xl-2 mb-3">
                <div class="card server-card h-100" data-server="${name}">
                    <div class="card-body text-center">
                        <div class="server-icon mb-3" style="color: ${server.color};">
                            <span style="font-size: 2rem;">${server.icon}</span>
                        </div>
                        <h6 class="card-title">${server.name}</h6>
                        <div class="server-status mb-2">
                            <span class="badge bg-secondary" id="status-${name}">
                                <i class="fas fa-circle"></i> 확인중
                            </span>
                        </div>
                        <small class="text-muted">포트: ${server.port}</small>
                        <br>
                        <small class="text-muted">${server.database}</small>
                    </div>
                </div>
            </div>
        `).join('');
    },

    renderVulnerabilityCategories() {
        return vulnerabilityCategories.map(category => `
            <div class="col-lg-6 col-xl-3 mb-4">
                <div class="card vulnerability-category h-100" data-priority="${category.priority}">
                    <div class="card-header d-flex align-items-center">
                        <i class="${category.icon} text-primary me-2"></i>
                        <h6 class="mb-0">${category.name}</h6>
                    </div>
                    <div class="card-body">
                        <p class="card-text text-muted small">${category.description}</p>
                        <div class="vulnerability-list">
                            ${category.vulnerabilities.map(vuln => `
                                <div class="d-flex align-items-center justify-content-between mb-2">
                                    <div class="d-flex align-items-center">
                                        <i class="${vuln.icon} text-muted me-2"></i>
                                        <small>${vuln.name}</small>
                                    </div>
                                    <div>
                                        ${vuln.status === 'completed' ?
                                            `<span class="badge bg-success cursor-pointer"
                                                   onclick="router.navigate('vulnerability/${vuln.type}')">
                                                실행
                                            </span>` :
                                            `<span class="badge bg-secondary">준비중</span>`
                                        }
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    <div class="card-footer">
                        <div class="progress" style="height: 4px;">
                            <div class="progress-bar ${this.getPriorityColorClass(category.priority)}"
                                 style="width: ${this.getCategoryProgress(category)}%"></div>
                        </div>
                        <div class="d-flex justify-content-between mt-2">
                            <small class="text-muted">진행률</small>
                            <small class="text-muted">${this.getCategoryProgress(category)}%</small>
                        </div>
                    </div>
                </div>
            </div>
        `).join('');
    },

    getPriorityColorClass(priority) {
        const classes = {
            high: 'bg-danger',
            medium: 'bg-warning',
            low: 'bg-info'
        };
        return classes[priority] || 'bg-secondary';
    },

    getCategoryProgress(category) {
        const total = category.vulnerabilities.length;
        const completed = category.vulnerabilities.filter(v => v.status === 'completed').length;
        return Math.round((completed / total) * 100);
    },

    async initialize() {
        // Check all server statuses
        await this.checkAllServers();

        // Set up periodic status checks
        setInterval(() => {
            this.checkAllServers();
        }, 30000); // Check every 30 seconds
    },

    async checkAllServers() {
        for (const [name, server] of Object.entries(languageServers)) {
            await this.checkServerStatus(name, server);
        }
    },

    async checkServerStatus(name, server) {
        const statusElement = document.getElementById(`status-${name}`);
        if (!statusElement) return;

        try {
            const response = await fetch(`http://localhost:${server.port}/health`, {
                method: 'GET',
                mode: 'cors',
                timeout: 5000
            });

            if (response.ok) {
                server.status = 'running';
                statusElement.className = 'badge bg-success';
                statusElement.innerHTML = '<i class="fas fa-circle"></i> 실행중';
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            server.status = 'offline';
            statusElement.className = 'badge bg-danger';
            statusElement.innerHTML = '<i class="fas fa-circle"></i> 오프라인';
            console.warn(`Server ${name} is offline:`, error.message);
        }
    }
};