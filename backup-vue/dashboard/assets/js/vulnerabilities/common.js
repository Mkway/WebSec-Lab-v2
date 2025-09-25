// 공통 유틸리티 함수들
export class VulnerabilityUtils {
    // 서버 상태 확인
    static async checkServerStatus(language, server) {
        try {
            const serverUrl = `http://localhost:${server.port}`;
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);

            const response = await fetch(`${serverUrl}/`, {
                mode: 'cors',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                server.status = 'running';
                console.log(`✅ Server ${language}: running`);
            } else {
                server.status = 'offline';
                console.log(`❌ Server ${language}: offline (HTTP ${response.status})`);
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                console.log(`⏰ Server ${language}: timeout`);
            } else {
                console.log(`❌ Server ${language} health check failed:`, error.message);
            }
            server.status = 'offline';
        }
    }

    // 언어별 Prism.js 클래스 매핑
    static getLanguageClass(language) {
        const languageMap = {
            'PHP': 'php',
            'Node.js': 'javascript',
            'Python': 'python',
            'Java': 'java',
            'Go': 'go'
        };
        return languageMap[language] || 'javascript';
    }

    // 위험도 클래스 반환
    static getRiskClass(level) {
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
    }

    // 딜레이 함수
    static delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // 코드 하이라이팅 업데이트
    static updateCodeHighlighting() {
        Vue.nextTick(() => {
            if (window.Prism) {
                Prism.highlightAll();
                this.addCopyButtons();
            }
        });
    }

    // 복사 버튼 추가
    static addCopyButtons() {
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
    }

    // 클립보드에 코드 복사
    static copyCodeToClipboard(text) {
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
    }

    // 성공 알림 표시
    static showSuccessAlert(message) {
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
    }

    // 에러 알림 표시
    static showErrorAlert(message) {
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
    }
}