// Simple SPA Router for WebSec-Lab Dashboard
export class Router {
    constructor() {
        this.routes = new Map();
        this.currentRoute = null;
        this.defaultRoute = 'dashboard';

        // Initialize router
        this.init();
    }

    // Route registration
    addRoute(path, component, config = {}) {
        this.routes.set(path, {
            component,
            title: config.title || path,
            requiresAuth: config.requiresAuth || false,
            meta: config.meta || {}
        });
        return this;
    }

    // Initialize router
    init() {
        // Handle browser back/forward
        window.addEventListener('popstate', (event) => {
            this.handleRouteChange();
        });

        // Handle initial load
        this.handleRouteChange();
    }

    // Get current route from URL
    getCurrentPath() {
        const hash = window.location.hash.slice(1) || '/';
        return hash.startsWith('/') ? hash.slice(1) : hash;
    }

    // Navigate to route
    navigate(path) {
        const targetPath = path.startsWith('/') ? path.slice(1) : path;

        if (this.currentRoute === targetPath) return;

        // Update browser history
        window.history.pushState({ path: targetPath }, '', `#/${targetPath}`);

        // Handle route change
        this.handleRouteChange();
    }

    // Handle route changes
    async handleRouteChange() {
        const path = this.getCurrentPath();
        console.log(`🔍 Handling route change: ${path}`);
        console.log(`📝 Available routes:`, Array.from(this.routes.keys()));

        const route = this.routes.get(path) || this.routes.get(this.defaultRoute);

        if (!route) {
            console.error(`❌ Route not found: ${path}`);
            console.log(`🔄 Navigating to default route: ${this.defaultRoute}`);
            this.navigate(this.defaultRoute);
            return;
        }

        try {
            // Update current route
            this.currentRoute = path;

            // Update document title
            document.title = `${route.title} - WebSec-Lab v2`;

            // Load and render component
            await this.renderComponent(route.component, path);

            // Update active navigation
            this.updateNavigation(path);

            console.log(`✅ Route changed to: ${path}`);

        } catch (error) {
            console.error(`❌ Failed to load route ${path}:`, error);
            this.navigate(this.defaultRoute);
        }
    }

    // Render component
    async renderComponent(component, path) {
        const container = document.getElementById('app-content');
        if (!container) {
            throw new Error('App content container not found');
        }

        // Show loading state
        container.innerHTML = `
            <div class="d-flex justify-content-center align-items-center" style="min-height: 400px;">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
        `;

        try {
            let content;

            if (typeof component === 'function') {
                // Dynamic component
                content = await component();
            } else if (typeof component === 'string') {
                // Static HTML string
                content = component;
            } else {
                throw new Error('Invalid component type');
            }

            container.innerHTML = content;

            // Trigger any post-render hooks
            this.triggerPostRender(path);

        } catch (error) {
            container.innerHTML = `
                <div class="alert alert-danger">
                    <h4>페이지 로드 실패</h4>
                    <p>요청한 페이지를 불러올 수 없습니다: ${error.message}</p>
                    <button class="btn btn-primary" onclick="router.navigate('dashboard')">
                        대시보드로 돌아가기
                    </button>
                </div>
            `;
            throw error;
        }
    }

    // Update navigation active states
    updateNavigation(currentPath) {
        // Update sidebar navigation
        document.querySelectorAll('[data-route]').forEach(navItem => {
            const routePath = navItem.getAttribute('data-route');
            if (routePath === currentPath) {
                navItem.classList.add('active');
            } else {
                navItem.classList.remove('active');
            }
        });

        // Update breadcrumb
        this.updateBreadcrumb(currentPath);
    }

    // Update breadcrumb
    updateBreadcrumb(path) {
        const breadcrumbContainer = document.querySelector('.breadcrumb-container');
        if (!breadcrumbContainer) return;

        const route = this.routes.get(path);
        if (!route) return;

        const breadcrumbHTML = `
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item">
                        <a href="#" onclick="router.navigate('dashboard')">
                            <i class="fas fa-home"></i> 대시보드
                        </a>
                    </li>
                    ${path !== 'dashboard' ? `
                        <li class="breadcrumb-item active" aria-current="page">
                            ${route.title}
                        </li>
                    ` : ''}
                </ol>
            </nav>
        `;

        breadcrumbContainer.innerHTML = breadcrumbHTML;
    }

    // Trigger post-render hooks
    triggerPostRender(path) {
        // Re-initialize syntax highlighting with error handling
        if (window.Prism) {
            try {
                console.log('🎨 Applying syntax highlighting...');

                // Wait for all Prism components to load
                setTimeout(() => {
                    try {
                        Prism.highlightAll();
                        console.log('✅ Syntax highlighting applied successfully');
                    } catch (error) {
                        console.warn('⚠️ Prism highlighting failed:', error.message);
                    }
                }, 100);

            } catch (error) {
                console.warn('⚠️ Prism not fully loaded:', error.message);
            }
        } else {
            console.warn('⚠️ Prism.js not available');
        }

        // Trigger custom event
        window.dispatchEvent(new CustomEvent('route-changed', {
            detail: { path }
        }));
    }

    // Get route data
    getRouteData(path = null) {
        const targetPath = path || this.currentRoute;
        return this.routes.get(targetPath);
    }

    // Check if route exists
    hasRoute(path) {
        return this.routes.has(path);
    }
}

// Create global router instance
export const router = new Router();

// Make router available globally
window.router = router;