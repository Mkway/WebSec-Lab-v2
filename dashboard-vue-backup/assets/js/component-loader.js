// Dynamic Component Loader
export class ComponentLoader {
    constructor() {
        this.loadedComponents = new Map();
        this.componentCache = new Map();
    }

    // 컴포넌트 HTML 파일 로드
    async loadComponent(componentName) {
        // 캐시에 있으면 캐시된 것을 반환
        if (this.componentCache.has(componentName)) {
            return this.componentCache.get(componentName);
        }

        try {
            const response = await fetch(`/components/${componentName}.html`);
            if (!response.ok) {
                throw new Error(`Failed to load component: ${componentName}`);
            }

            const html = await response.text();

            // 캐시에 저장
            this.componentCache.set(componentName, html);

            console.log(`✅ Component loaded: ${componentName}`);
            return html;
        } catch (error) {
            console.error(`❌ Error loading component ${componentName}:`, error);
            return `<div class="alert alert-danger">
                <i class="fas fa-exclamation-triangle"></i>
                컴포넌트 로드 실패: ${componentName}
            </div>`;
        }
    }

    // 특정 컨테이너에 컴포넌트 렌더링
    async renderComponent(componentName, containerId = 'dynamic-content') {
        const container = document.getElementById(containerId);
        if (!container) {
            console.error(`❌ Container not found: ${containerId}`);
            return false;
        }

        // 로딩 상태 표시
        container.innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
                <div class="mt-3">
                    <small class="text-muted">${componentName} 컴포넌트 로딩 중...</small>
                </div>
            </div>
        `;

        try {
            const componentHtml = await this.loadComponent(componentName);
            container.innerHTML = componentHtml;

            // 컴포넌트 로드 완료 이벤트 발생
            const event = new CustomEvent('componentLoaded', {
                detail: { componentName, containerId }
            });
            document.dispatchEvent(event);

            console.log(`🎯 Component rendered: ${componentName} in ${containerId}`);
            return true;
        } catch (error) {
            console.error(`❌ Error rendering component:`, error);
            container.innerHTML = `
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    컴포넌트 렌더링 실패
                </div>
            `;
            return false;
        }
    }

    // 메인 대시보드 로드
    async renderMainDashboard() {
        return await this.renderComponent('main-dashboard', 'app-content');
    }

    // 컴포넌트 캐시 클리어
    clearCache() {
        this.componentCache.clear();
        console.log('🧹 Component cache cleared');
    }

    // 프리로드 (자주 사용되는 컴포넌트들을 미리 로드)
    async preloadComponents(componentNames) {
        console.log('🚀 Preloading components...', componentNames);

        const loadPromises = componentNames.map(name =>
            this.loadComponent(name).catch(error => {
                console.warn(`⚠️ Failed to preload ${name}:`, error);
                return null;
            })
        );

        await Promise.all(loadPromises);
        console.log('✅ Component preloading completed');
    }
}

// 전역 인스턴스
export const componentLoader = new ComponentLoader();