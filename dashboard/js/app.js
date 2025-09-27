// WebSec-Lab v2 - Simple Dashboard JavaScript
// 핵심 기능만 포함한 간단한 구현

// 서버 정보 설정
const SERVERS = {
    php: {
        port: 8080,
        name: 'PHP',
        icon: '🐘',
        swaggerUrl: 'http://localhost:8080/swagger-ui',
        docsUrl: 'http://localhost:8080/docs',
        jsonUrl: 'http://localhost:8080/swagger.json'
    },
    nodejs: {
        port: 3000,
        name: 'Node.js',
        icon: '🟢',
        swaggerUrl: 'http://localhost:3000/swagger-ui',
        docsUrl: 'http://localhost:3000/docs',
        jsonUrl: 'http://localhost:3000/swagger.json'
    },
    python: {
        port: 5000,
        name: 'Python',
        icon: '🐍',
        swaggerUrl: 'http://localhost:5000/docs',
        docsUrl: 'http://localhost:5000/',
        jsonUrl: 'http://localhost:5000/swagger.json'
    },
    java: {
        port: 8081,
        name: 'Java',
        icon: '☕',
        swaggerUrl: 'http://localhost:8081/swagger-ui/index.html',
        docsUrl: 'http://localhost:8081/',
        jsonUrl: 'http://localhost:8081/v3/api-docs'
    },
    go: {
        port: 8082,
        name: 'Go',
        icon: '🔵',
        swaggerUrl: 'http://localhost:8082/swagger/index.html',
        docsUrl: 'http://localhost:8082/',
        jsonUrl: 'http://localhost:8082/swagger/doc.json'
    }
};

// 페이로드 데이터
const PAYLOADS = {
    sql: {
        basic: { username: "admin' OR '1'='1", password: "' OR '1'='1" },
        comment: { username: "admin'--", password: "anything" },
        union: { username: "' UNION SELECT user(),version()--", password: "anything" }
    },
    xss: {
        basic: '<script>alert("XSS")</script>',
        img: '<img src=x onerror=alert("XSS")>',
        svg: '<svg onload=alert("XSS")>'
    }
};

// DOM 요소들
let elements = {};
let currentVulnerability = 'sql-injection'; // 기본값

// 초기화
document.addEventListener('DOMContentLoaded', function() {
    initializeElements();
    setupEventListeners();
    checkServerStatus();
    updateVulnerabilityInputs();

    // XSS textarea 기본값 강제 설정
    setTimeout(() => {
        if (elements.xssPayload && (!elements.xssPayload.value || elements.xssPayload.value.trim() === '')) {
            elements.xssPayload.value = '<script>alert("XSS")</script>';
        }
    }, 100);
});

// DOM 요소 초기화
function initializeElements() {
    elements = {
        vulnItems: document.querySelectorAll('.vuln-sidebar-item'),
        sqlInputs: document.getElementById('sql-inputs'),
        xssInputs: document.getElementById('xss-inputs'),
        sqlUsername: document.getElementById('sql-username'),
        sqlPassword: document.getElementById('sql-password'),
        xssPayload: document.getElementById('xss-payload'),
        testBtn: document.getElementById('test-btn'),
        loading: document.getElementById('loading'),
        results: document.getElementById('results'),
        resultsContent: document.getElementById('results-content'),
        serverStatus: document.getElementById('server-status-content')
    };

    // 요소 존재 여부 확인 및 오류 방지
    console.log('Elements initialized:', {
        sqlUsername: elements.sqlUsername !== null,
        sqlPassword: elements.sqlPassword !== null,
        xssPayload: elements.xssPayload !== null
    });
}

// 이벤트 리스너 설정
function setupEventListeners() {
    // 취약점 유형 선택 이벤트
    elements.vulnItems.forEach(item => {
        item.addEventListener('click', function() {
            // disabled 상태면 무시
            if (this.hasAttribute('disabled')) return;

            // 모든 아이템에서 active 클래스 제거
            elements.vulnItems.forEach(i => i.classList.remove('active'));
            // 클릭된 아이템에 active 클래스 추가
            this.classList.add('active');
            // 현재 취약점 유형 업데이트
            currentVulnerability = this.getAttribute('data-type');
            updateVulnerabilityInputs();

            // 결과 숨기기
            hideResults();
        });
    });
}

// 취약점 유형에 따른 입력 폼 표시/숨김
function updateVulnerabilityInputs() {
    if (currentVulnerability === 'sql-injection') {
        elements.sqlInputs.style.display = 'block';
        elements.xssInputs.style.display = 'none';
    } else if (currentVulnerability === 'xss') {
        elements.sqlInputs.style.display = 'none';
        elements.xssInputs.style.display = 'block';

        // XSS textarea에 기본값이 없으면 설정
        if (!elements.xssPayload.value || elements.xssPayload.value.trim() === '') {
            elements.xssPayload.value = '<script>alert("XSS")</script>';
        }
    }
}

// SQL 페이로드 적용
function applySqlPayload(type) {
    const payload = PAYLOADS.sql[type];
    if (payload) {
        elements.sqlUsername.value = payload.username;
        elements.sqlPassword.value = payload.password;
        showMessage('🎯 SQL 페이로드가 적용되었습니다!', 'success');
    }
}

// XSS 페이로드 적용
function applyXssPayload(type) {
    const payload = PAYLOADS.xss[type];
    if (payload) {
        elements.xssPayload.value = payload;
        showMessage('🎯 XSS 페이로드가 적용되었습니다!', 'success');
    }
}

// 메인 테스트 실행 함수 - 모든 언어 동시 테스트
async function runTest() {
    const vulnerability = currentVulnerability;

    console.log('🔍 Starting runTest with vulnerability:', vulnerability);
    console.log('🔍 Elements check:', {
        sqlUsername: elements.sqlUsername,
        sqlPassword: elements.sqlPassword,
        xssPayload: elements.xssPayload
    });

    // 로딩 상태 표시
    showLoading(true);
    hideResults();

    try {
        // 모든 언어에 대해 동시에 테스트 실행
        const allResults = [];

        for (const language of Object.keys(SERVERS)) {
            try {
                // 각 언어별로 취약한 버전과 안전한 버전 모두 테스트
                const vulnerableResult = await executeTest(language, vulnerability, 'vulnerable');
                const safeResult = await executeTest(language, vulnerability, 'safe');

                allResults.push({
                    language,
                    vulnerableResult,
                    safeResult
                });
            } catch (error) {
                console.error(`Error testing ${language}:`, error);
                // 오류가 발생한 언어는 오류 결과로 추가
                allResults.push({
                    language,
                    error: error.message
                });
            }
        }

        displayAllLanguageResults(allResults);
        showMessage('✅ 모든 언어 비교 분석이 완료되었습니다!', 'success');

    } catch (error) {
        console.error('Test error:', error);
        showMessage(`❌ 테스트 중 오류가 발생했습니다: ${error.message}`, 'error');
    } finally {
        showLoading(false);
    }
}

// 개별 테스트 실행
async function executeTest(language, vulnerability, mode) {
    const server = SERVERS[language];
    const serverUrl = `http://localhost:${server.port}`;

    let requestData = {};
    let endpoint = '';

    if (vulnerability === 'sql-injection') {
        endpoint = '/vulnerabilities/sql-injection';
        // 요소 존재 여부 확인
        const username = elements.sqlUsername ? elements.sqlUsername.value : "admin' OR '1'='1";
        const password = elements.sqlPassword ? elements.sqlPassword.value : "' OR '1'='1";

        requestData = {
            mode: mode,
            username: username,
            password: password,
            payload: username,
            target: 'login'
        };
    } else if (vulnerability === 'xss') {
        endpoint = '/vulnerabilities/xss';

        // XSS 페이로드 값 강제 확인 및 설정
        let xssPayload = elements.xssPayload ? elements.xssPayload.value : '';
        if (!xssPayload || xssPayload.trim() === '') {
            xssPayload = '<script>alert("XSS")</script>';
            if (elements.xssPayload) {
                elements.xssPayload.value = xssPayload;
            }
        }

        requestData = {
            mode: mode,
            payload: xssPayload,
            target: 'search'
        };

        console.log('XSS payload being sent:', xssPayload);
    }

    console.log(`🔍 Testing ${language} ${vulnerability} (${mode}):`, requestData);

    const response = await fetch(`${serverUrl}${endpoint}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData)
    });

    if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    return {
        language: language,
        vulnerability: vulnerability,
        mode: mode,
        success: response.ok,
        data: data,
        status: response.status,
        requestData: requestData
    };
}

// 모든 언어 결과 표시 (접히는 카드 형식)
function displayAllLanguageResults(allResults) {
    const currentTime = Date.now();
    let html = `
        <div class="all-languages-results">
            <div class="results-header">
                <h2>🌍 모든 언어 취약점 비교 분석</h2>
                <p>총 ${allResults.length}개 언어에서 동시 테스트 결과</p>
                <div class="expand-all-controls">
                    <button onclick="expandAllCards()" class="control-btn expand-btn">📂 모든 카드 열기</button>
                    <button onclick="collapseAllCards()" class="control-btn collapse-btn">📁 모든 카드 접기</button>
                </div>
            </div>
    `;

    // 각 언어별 결과 카드
    allResults.forEach((result, index) => {
        const cardId = `card-${result.language}-${currentTime}`;
        const contentId = `content-${result.language}-${currentTime}`;

        if (result.error) {
            html += `
                <div class="language-result-card error-card" id="${cardId}">
                    <div class="card-header" onclick="toggleCard('${contentId}', this)">
                        <div class="card-title">
                            <span class="server-info">${SERVERS[result.language].icon} ${SERVERS[result.language].name}</span>
                            <span class="status-badge error">❌ 테스트 실패</span>
                        </div>
                        <div class="toggle-icon">▼</div>
                    </div>
                    <div class="card-content collapsed" id="${contentId}">
                        <div class="error-details">
                            <h4>오류 정보</h4>
                            <div class="error-message">${result.error}</div>
                        </div>
                    </div>
                </div>
            `;
        } else {
            const server = SERVERS[result.language];
            const vulnerableResult = result.vulnerableResult;
            const safeResult = result.safeResult;

            // 공격 성공 여부 확인
            let attackSuccess = false;
            if (currentVulnerability === 'sql-injection') {
                attackSuccess = vulnerableResult.data?.result?.authentication_bypassed || vulnerableResult.data?.success === true;
            } else if (currentVulnerability === 'xss') {
                attackSuccess = vulnerableResult.data?.data?.attack_success || vulnerableResult.data?.data?.vulnerability_detected;
            }

            html += `
                <div class="language-result-card ${attackSuccess ? 'vulnerable' : 'safe'}" id="${cardId}">
                    <div class="card-header" onclick="toggleCard('${contentId}', this)">
                        <div class="card-title">
                            <span class="server-info">${server.icon} ${server.name} (포트: ${server.port})</span>
                            <span class="status-badge ${attackSuccess ? 'vulnerable' : 'safe'}">
                                ${attackSuccess ? '⚠️ 취약점 발견' : '✅ 안전'}
                            </span>
                        </div>
                        <div class="toggle-icon">▼</div>
                    </div>
                    <div class="card-content collapsed" id="${contentId}">
                        <div class="vulnerability-analysis">
                            ${ComparisonRenderer.render(vulnerableResult, safeResult)}
                        </div>
                    </div>
                </div>
            `;
        }
    });

    html += `</div>`;
    elements.resultsContent.innerHTML = html;
    showResults();
}

// 카드 토글 함수
function toggleCard(contentId, headerElement) {
    const content = document.getElementById(contentId);
    const icon = headerElement.querySelector('.toggle-icon');

    if (content.classList.contains('collapsed')) {
        content.classList.remove('collapsed');
        content.classList.add('expanded');
        icon.textContent = '▲';
        headerElement.classList.add('active');
    } else {
        content.classList.remove('expanded');
        content.classList.add('collapsed');
        icon.textContent = '▼';
        headerElement.classList.remove('active');
    }
}

// 모든 카드 열기/접기
function expandAllCards() {
    document.querySelectorAll('.card-content.collapsed').forEach(content => {
        const cardId = content.id;
        const header = document.querySelector(`[onclick*="${cardId}"]`);
        if (header) {
            toggleCard(cardId, header);
        }
    });
}

function collapseAllCards() {
    document.querySelectorAll('.card-content.expanded').forEach(content => {
        const cardId = content.id;
        const header = document.querySelector(`[onclick*="${cardId}"]`);
        if (header) {
            toggleCard(cardId, header);
        }
    });
}

// 결과 표시 (단일 언어 비교 분석 버전)
function displayResults(results) {
    // results 배열에서 취약한 버전과 안전한 버전 분리
    const vulnerableResult = results.find(r => r.mode === 'vulnerable');
    const safeResult = results.find(r => r.mode === 'safe');

    if (!vulnerableResult || !safeResult) {
        elements.resultsContent.innerHTML = '<div class="error">비교할 결과가 부족합니다.</div>';
        showResults();
        return;
    }

    // 비교 분석 렌더링
    const comparisonHtml = ComparisonRenderer.render(vulnerableResult, safeResult);

    // 원시 데이터 섹션 추가
    const rawDataId = 'raw-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    const rawDataHtml = `
        <div class="raw-data-section">
            <button onclick="toggleRawData('${rawDataId}')" class="toggle-button">
                📊 기술적 데이터 보기/숨기기 (개발자용)
            </button>
            <div id="${rawDataId}" class="raw-data" style="display: none;">
                <div class="raw-data-grid">
                    <div class="raw-data-item">
                        <h4>취약한 버전 응답</h4>
                        <div class="result-content">${JSON.stringify(vulnerableResult.data, null, 2)}</div>
                    </div>
                    <div class="raw-data-item">
                        <h4>안전한 버전 응답</h4>
                        <div class="result-content">${JSON.stringify(safeResult.data, null, 2)}</div>
                    </div>
                </div>
            </div>
        </div>
    `;

    elements.resultsContent.innerHTML = comparisonHtml + rawDataHtml;
    showResults();
}

// 원시 데이터 토글 함수
function toggleRawData(id) {
    const element = document.getElementById(id);
    if (element) {
        element.style.display = element.style.display === 'none' ? 'block' : 'none';
    }
}

// 서버 상태 확인
async function checkServerStatus() {
    let html = '서버 상태를 확인하고 있습니다...<br><br>';
    elements.serverStatus.innerHTML = html;

    const statusPromises = Object.entries(SERVERS).map(async ([key, server]) => {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);

            const response = await fetch(`http://localhost:${server.port}/health`, {
                method: 'GET',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            return {
                key: key,
                name: server.name,
                icon: server.icon,
                status: response.ok ? 'running' : 'error',
                port: server.port
            };
        } catch (error) {
            return {
                key: key,
                name: server.name,
                icon: server.icon,
                status: 'offline',
                port: server.port
            };
        }
    });

    const results = await Promise.all(statusPromises);

    html = '';
    results.forEach(result => {
        const statusClass = result.status === 'running' ? 'status-running' : 'status-offline';
        const statusText = result.status === 'running' ? '✅ 실행 중' : '❌ 오프라인';

        html += `
            <div class="server-item">
                <div class="server-name">
                    ${result.icon} ${result.name} (포트: ${result.port})
                </div>
                <div class="status-indicator ${statusClass}">
                    ${statusText}
                </div>
                ${result.status === 'running' ? `
                    <div class="swagger-links">
                        <a href="${SERVERS[result.key].swaggerUrl}" target="_blank" class="swagger-link" title="Swagger UI 열기">
                            📖 API 문서
                        </a>
                    </div>
                ` : ''}
            </div>
        `;
    });

    elements.serverStatus.innerHTML = html;
}

// 유틸리티 함수들
function showLoading(show) {
    console.log('🔍 showLoading called with:', show);
    console.log('🔍 elements.loading:', elements.loading);
    console.log('🔍 elements.testBtn:', elements.testBtn);

    if (elements.loading) {
        elements.loading.style.display = show ? 'block' : 'none';
    }
    if (elements.testBtn) {
        elements.testBtn.disabled = show;
    }
}

function showResults() {
    elements.results.style.display = 'block';
}

function hideResults() {
    elements.results.style.display = 'none';
}

function showMessage(message, type) {
    // 간단한 알림 표시 (실제로는 더 나은 UI를 사용할 수 있음)
    const color = type === 'success' ? '#51cf66' : '#ff6b6b';
    const originalBg = document.body.style.background;

    // 임시로 바디 배경색 변경으로 피드백 제공
    document.body.style.transition = 'background-color 0.3s ease';
    document.body.style.backgroundColor = color + '20';

    setTimeout(() => {
        document.body.style.backgroundColor = '';
        document.body.style.background = originalBg;
    }, 500);

    console.log(`[${type.toUpperCase()}] ${message}`);
}