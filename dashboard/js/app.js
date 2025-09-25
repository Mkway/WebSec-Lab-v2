// WebSec-Lab v2 - Simple Dashboard JavaScript
// 핵심 기능만 포함한 간단한 구현

// 서버 정보 설정
const SERVERS = {
    php: { port: 8080, name: 'PHP', icon: '🐘' },
    nodejs: { port: 3000, name: 'Node.js', icon: '🟢' },
    python: { port: 5000, name: 'Python', icon: '🐍' },
    java: { port: 8081, name: 'Java', icon: '☕' },
    go: { port: 8082, name: 'Go', icon: '🔵' }
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
        language: document.getElementById('language'),
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

// 메인 테스트 실행 함수
async function runTest() {
    const language = elements.language.value;
    const vulnerability = currentVulnerability;

    // 서버 상태 확인
    const server = SERVERS[language];
    if (!server) {
        showMessage('잘못된 언어가 선택되었습니다.', 'error');
        return;
    }

    // 로딩 상태 표시
    showLoading(true);
    hideResults();

    try {
        // 항상 취약한 버전과 안전한 버전 모두 테스트
        const vulnerableResult = await executeTest(language, vulnerability, 'vulnerable');
        const safeResult = await executeTest(language, vulnerability, 'safe');

        const results = [vulnerableResult, safeResult];
        displayResults(results);
        showMessage('✅ 비교 분석이 완료되었습니다!', 'success');

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
        requestData = {
            mode: mode,
            username: elements.sqlUsername.value,
            password: elements.sqlPassword.value,
            payload: elements.sqlUsername.value,
            target: 'login'
        };
    } else if (vulnerability === 'xss') {
        endpoint = '/vulnerabilities/xss';

        // XSS 페이로드 값 강제 확인 및 설정
        let xssPayload = elements.xssPayload.value;
        if (!xssPayload || xssPayload.trim() === '') {
            xssPayload = '<script>alert("XSS")</script>';
            elements.xssPayload.value = xssPayload;
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

// 결과 표시 (비교 분석 버전)
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
            </div>
        `;
    });

    elements.serverStatus.innerHTML = html;
}

// 유틸리티 함수들
function showLoading(show) {
    elements.loading.style.display = show ? 'block' : 'none';
    elements.testBtn.disabled = show;
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