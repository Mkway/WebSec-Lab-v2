// Main Application Entry Point
import { router } from './router.js?v=3';
import { NavigationComponent } from './components/navigation.js?v=3';
import { DashboardPage } from './pages/dashboard.js?v=3';
import { SQLInjectionPage } from './pages/sql-injection.js?v=3';
import { XSSPage } from './pages/xss.js?v=3';

// Application Class
class WebSecLabApp {
    constructor() {
        this.isInitialized = false;
        this.currentPage = null;
    }

    async initialize() {
        if (this.isInitialized) return;

        console.log('🚀 Initializing WebSec-Lab v2 Dashboard...');

        try {
            // Register routes first
            this.registerRoutes();

            // Initialize router
            router.init();

            // Initialize navigation after router is ready
            await this.initializeNavigation();

            // Load theme
            NavigationComponent.loadTheme();

            this.isInitialized = true;
            console.log('✅ WebSec-Lab v2 Dashboard initialized successfully');

        } catch (error) {
            console.error('❌ Failed to initialize application:', error);
            this.showErrorMessage('애플리케이션 초기화에 실패했습니다.');
        }
    }

    async initializeNavigation() {
        const navContainer = document.getElementById('navigation-container');
        if (!navContainer) {
            throw new Error('Navigation container not found');
        }

        // Render navigation
        navContainer.innerHTML = NavigationComponent.render();

        // Initialize navigation component
        NavigationComponent.initialize();

        console.log('✅ Navigation initialized');
    }

    registerRoutes() {
        // Dashboard route
        router.addRoute('dashboard', async () => {
            const html = await DashboardPage.render();
            setTimeout(() => {
                DashboardPage.initialize();
            }, 100);
            return html;
        }, {
            title: '대시보드',
            meta: { description: 'WebSec-Lab v2 메인 대시보드' }
        });

        // SQL Injection route
        router.addRoute('vulnerability/sql-injection', async () => {
            const html = await SQLInjectionPage.render();
            setTimeout(() => {
                SQLInjectionPage.initialize();
            }, 100);
            return html;
        }, {
            title: 'SQL Injection',
            meta: { description: 'SQL 인젝션 취약점 테스트' }
        });

        // XSS route
        router.addRoute('vulnerability/xss', async () => {
            const html = await XSSPage.render();
            setTimeout(() => {
                XSSPage.initialize();
            }, 100);
            return html;
        }, {
            title: 'Cross-Site Scripting',
            meta: { description: 'XSS 취약점 테스트' }
        });

        // Command Injection route (placeholder)
        router.addRoute('vulnerability/command-injection', async () => {
            return this.renderPlaceholderPage('Command Injection', '명령어 주입 취약점 테스트는 곧 구현될 예정입니다.');
        }, {
            title: 'Command Injection',
            meta: { description: '명령어 주입 취약점 테스트 (준비중)' }
        });

        // Tools route (placeholder)
        router.addRoute('tools', async () => {
            return this.renderToolsPage();
        }, {
            title: '보안 도구',
            meta: { description: '웹 보안 분석 및 테스트 도구' }
        });

        // Documentation route (placeholder)
        router.addRoute('docs', async () => {
            return this.renderDocumentationPage();
        }, {
            title: '문서',
            meta: { description: 'WebSec-Lab v2 사용 가이드' }
        });

        // Settings route (placeholder)
        router.addRoute('settings', async () => {
            return this.renderSettingsPage();
        }, {
            title: '설정',
            meta: { description: '대시보드 설정' }
        });

        // About route (placeholder)
        router.addRoute('about', async () => {
            return this.renderAboutPage();
        }, {
            title: '정보',
            meta: { description: 'WebSec-Lab v2 정보' }
        });

        console.log('✅ Routes registered');
    }

    renderPlaceholderPage(title, description) {
        return `
            <div class="placeholder-page">
                <div class="row">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <div class="text-center py-5">
                            <div class="mb-4">
                                <i class="fas fa-construction fa-4x text-muted"></i>
                            </div>
                            <h2>${title}</h2>
                            <p class="lead text-muted">${description}</p>
                            <button class="btn btn-primary" onclick="router.navigate('dashboard')">
                                <i class="fas fa-home"></i> 대시보드로 돌아가기
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderToolsPage() {
        return `
            <div class="tools-page">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <h1><i class="fas fa-tools text-secondary"></i> 보안 도구</h1>
                        <p class="lead">웹 보안 분석 및 테스트를 위한 다양한 도구들</p>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-6 col-lg-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-search fa-3x text-primary mb-3"></i>
                                <h5>Vulnerability Scanner</h5>
                                <p class="text-muted">자동화된 취약점 스캐닝 도구</p>
                                <button class="btn btn-outline-primary" disabled>준비중</button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-code fa-3x text-success mb-3"></i>
                                <h5>Payload Generator</h5>
                                <p class="text-muted">다양한 공격 페이로드 생성기</p>
                                <button class="btn btn-outline-success" disabled>준비중</button>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6 col-lg-4 mb-4">
                        <div class="card h-100">
                            <div class="card-body text-center">
                                <i class="fas fa-chart-line fa-3x text-info mb-3"></i>
                                <h5>Report Generator</h5>
                                <p class="text-muted">테스트 결과 리포트 생성</p>
                                <button class="btn btn-outline-info" disabled>준비중</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderDocumentationPage() {
        return `
            <div class="documentation-page">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <h1><i class="fas fa-book text-info"></i> 문서</h1>
                        <p class="lead">WebSec-Lab v2 사용 가이드 및 문서</p>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-4 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-rocket"></i> 시작하기</h5>
                            </div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li><a href="#" class="text-decoration-none">설치 가이드</a></li>
                                    <li><a href="#" class="text-decoration-none">첫 번째 테스트 실행</a></li>
                                    <li><a href="#" class="text-decoration-none">환경 설정</a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-bug"></i> 취약점 가이드</h5>
                            </div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li><a href="#" class="text-decoration-none">SQL Injection</a></li>
                                    <li><a href="#" class="text-decoration-none">Cross-Site Scripting</a></li>
                                    <li><a href="#" class="text-decoration-none">Command Injection</a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4 mb-4">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-cog"></i> API 문서</h5>
                            </div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li><a href="#" class="text-decoration-none">REST API 참조</a></li>
                                    <li><a href="#" class="text-decoration-none">인증 방법</a></li>
                                    <li><a href="#" class="text-decoration-none">응답 형식</a></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderSettingsPage() {
        return `
            <div class="settings-page">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <h1><i class="fas fa-cog text-secondary"></i> 설정</h1>
                        <p class="lead">대시보드 및 테스트 환경 설정</p>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-palette"></i> 테마 설정</h5>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <button class="btn btn-outline-dark me-2" onclick="NavigationComponent.toggleTheme()">
                                        <i class="fas fa-sun"></i> 라이트 모드
                                    </button>
                                    <button class="btn btn-outline-light me-2" onclick="NavigationComponent.toggleTheme()">
                                        <i class="fas fa-moon"></i> 다크 모드
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div class="card mt-4">
                            <div class="card-header">
                                <h5><i class="fas fa-server"></i> 서버 설정</h5>
                            </div>
                            <div class="card-body">
                                <div class="alert alert-info">
                                    <i class="fas fa-info-circle"></i>
                                    서버 설정은 Docker Compose를 통해 관리됩니다.
                                </div>
                                <ul class="list-unstyled">
                                    <li><strong>PHP:</strong> localhost:8080</li>
                                    <li><strong>Node.js:</strong> localhost:3000</li>
                                    <li><strong>Python:</strong> localhost:5000</li>
                                    <li><strong>Java:</strong> localhost:8081</li>
                                    <li><strong>Go:</strong> localhost:8082</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header">
                                <h5><i class="fas fa-info-circle"></i> 정보</h5>
                            </div>
                            <div class="card-body">
                                <ul class="list-unstyled">
                                    <li><strong>버전:</strong> v2.0.0</li>
                                    <li><strong>빌드:</strong> ${new Date().toISOString().split('T')[0]}</li>
                                    <li><strong>환경:</strong> Development</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    renderAboutPage() {
        return `
            <div class="about-page">
                <div class="row mb-4">
                    <div class="col-12">
                        <div class="breadcrumb-container"></div>
                        <div class="text-center">
                            <h1><i class="fas fa-shield-alt text-primary"></i> WebSec-Lab v2</h1>
                            <p class="lead">실전 웹 보안 취약점 학습 플랫폼</p>
                        </div>
                    </div>
                </div>

                <div class="row">
                    <div class="col-md-8 mx-auto">
                        <div class="card">
                            <div class="card-body">
                                <h5><i class="fas fa-target"></i> 프로젝트 목표</h5>
                                <p>WebSec-Lab v2는 실제 웹 보안 취약점을 안전한 환경에서 학습하고 테스트할 수 있는 통합 플랫폼입니다.</p>

                                <h5><i class="fas fa-star"></i> 주요 특징</h5>
                                <ul>
                                    <li>다중 언어 지원 (PHP, Node.js, Python, Java, Go)</li>
                                    <li>실전 공격 페이로드 (PayloadsAllTheThings 통합)</li>
                                    <li>실시간 비교 테스트</li>
                                    <li>모던 웹 UI 대시보드</li>
                                </ul>

                                <h5><i class="fas fa-code"></i> 기술 스택</h5>
                                <ul>
                                    <li><strong>Frontend:</strong> Vanilla JavaScript, Bootstrap 5</li>
                                    <li><strong>Backend:</strong> Multi-language servers</li>
                                    <li><strong>Infrastructure:</strong> Docker Compose</li>
                                    <li><strong>Security:</strong> PayloadsAllTheThings</li>
                                </ul>

                                <div class="text-center mt-4">
                                    <button class="btn btn-primary" onclick="router.navigate('dashboard')">
                                        <i class="fas fa-home"></i> 대시보드로 돌아가기
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    showErrorMessage(message) {
        const container = document.getElementById('app-content');
        if (container) {
            container.innerHTML = `
                <div class="alert alert-danger text-center">
                    <h4><i class="fas fa-exclamation-triangle"></i> 오류 발생</h4>
                    <p>${message}</p>
                    <button class="btn btn-primary" onclick="location.reload()">
                        <i class="fas fa-refresh"></i> 새로고침
                    </button>
                </div>
            `;
        }
    }
}

// Initialize application
document.addEventListener('DOMContentLoaded', async () => {
    const app = new WebSecLabApp();
    await app.initialize();
});

// Make app available globally for debugging
window.WebSecLabApp = WebSecLabApp;