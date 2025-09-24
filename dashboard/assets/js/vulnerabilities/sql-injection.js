// SQL Injection 취약점 테스트 모듈
import { languageServers } from '../config/servers.js';
import { VulnerabilityUtils } from './common.js';

export class SQLInjectionModule {
    constructor() {
        this.results = {};
        this.currentTest = null;
    }

    // SQL Injection 테스트 인터페이스 렌더링
    renderInterface() {
        return `
            <div class="vulnerability-section" id="sql-injection-section">
                <div class="d-flex justify-content-between align-items-center mb-4">
                    <div>
                        <h3 class="text-danger mb-2">
                            <i class="fas fa-database"></i> SQL Injection Testing
                        </h3>
                        <p class="text-muted">다양한 언어와 데이터베이스에서 SQL Injection 취약점을 테스트합니다.</p>
                    </div>
                </div>

                <!-- 데이터베이스 매핑 정보 -->
                <div class="alert alert-info mb-4">
                    <h6><i class="fas fa-info-circle"></i> 언어별 데이터베이스 매핑</h6>
                    <div class="row">
                        <div class="col-md-6">
                            <ul class="list-unstyled mb-0">
                                <li><strong>🐘 PHP:</strong> MySQL</li>
                                <li><strong>💚 Node.js:</strong> MongoDB (NoSQL Injection)</li>
                                <li><strong>🐍 Python:</strong> PostgreSQL</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <ul class="list-unstyled mb-0">
                                <li><strong>☕ Java:</strong> H2 Database</li>
                                <li><strong>🐹 Go:</strong> MySQL</li>
                            </ul>
                        </div>
                    </div>
                </div>

                <!-- 테스트 폼 -->
                <div class="card border-danger">
                    <div class="card-header bg-danger text-white">
                        <h5 class="mb-0"><i class="fas fa-vial"></i> SQL Injection 테스트</h5>
                    </div>
                    <div class="card-body">
                        <form id="sql-injection-form">
                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label class="form-label fw-bold">사용자명</label>
                                    <input type="text" id="sql-username" class="form-control"
                                           placeholder="admin' OR '1'='1" value="admin">
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label fw-bold">비밀번호</label>
                                    <input type="text" id="sql-password" class="form-control"
                                           placeholder="' OR '1'='1" value="password">
                                </div>
                            </div>

                            <div class="row mb-3">
                                <div class="col-md-6">
                                    <label class="form-label fw-bold">테스트 모드</label>
                                    <select id="sql-test-mode" class="form-select">
                                        <option value="vulnerable">🚨 취약한 코드 테스트</option>
                                        <option value="safe">🛡️ 안전한 코드 테스트</option>
                                    </select>
                                </div>
                                <div class="col-md-6">
                                    <label class="form-label fw-bold">대상 언어</label>
                                    <select id="sql-target-language" class="form-select">
                                        <option value="all">🌐 모든 언어</option>
                                        <option value="PHP">🐘 PHP (MySQL)</option>
                                        <option value="Node.js">💚 Node.js (MongoDB)</option>
                                        <option value="Python">🐍 Python (PostgreSQL)</option>
                                        <option value="Java">☕ Java (H2)</option>
                                        <option value="Go">🐹 Go (MySQL)</option>
                                    </select>
                                </div>
                            </div>

                            <div class="text-center">
                                <button type="submit" class="btn btn-danger btn-lg px-4 me-2">
                                    <i class="fas fa-play"></i> SQL Injection 테스트 실행
                                </button>
                                <button type="button" class="btn btn-secondary" onclick="sqlInjectionModule.clearResults()">
                                    <i class="fas fa-trash"></i> 결과 초기화
                                </button>
                            </div>
                        </form>
                    </div>
                </div>

                <!-- 일반적인 SQL Injection 페이로드 -->
                <div class="card mt-4">
                    <div class="card-header">
                        <h6 class="mb-0"><i class="fas fa-list"></i> 일반적인 SQL Injection 페이로드</h6>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>인증 우회</h6>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>admin' OR '1'='1</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>' OR 1=1--</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>admin'/*</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>MongoDB (NoSQL) 페이로드</h6>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>admin' || '1'=='1</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>{"$where": "1==1"}</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                                <div class="bg-light p-2 rounded mb-2">
                                    <code>{"$regex": ".*"}</code>
                                    <button class="btn btn-sm btn-outline-primary float-end"
                                            onclick="document.getElementById('sql-username').value = this.previousElementSibling.textContent">사용</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 결과 영역 -->
                <div id="sql-results-section" class="mt-4" style="display: none;">
                    <div class="card">
                        <div class="card-header">
                            <h5 class="mb-0"><i class="fas fa-chart-bar"></i> 테스트 결과</h5>
                        </div>
                        <div class="card-body" id="sql-results-content">
                            <!-- 결과가 여기에 표시됩니다 -->
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // SQL Injection 테스트 실행
    async executeSQLTest(username, password, mode, targetLanguage) {
        const results = [];
        this.currentTest = { username, password, mode, targetLanguage };

        if (targetLanguage === 'all') {
            // 모든 언어에 대해 테스트
            for (const [language, server] of Object.entries(languageServers)) {
                if (server.status === 'running') {
                    const result = await this.testSingleLanguage(language, server, username, password, mode);
                    results.push(result);
                    await VulnerabilityUtils.delay(500);
                }
            }
        } else {
            // 특정 언어만 테스트
            const server = languageServers[targetLanguage];
            if (server && server.status === 'running') {
                const result = await this.testSingleLanguage(targetLanguage, server, username, password, mode);
                results.push(result);
            }
        }

        this.results = results;
        this.displayResults(results);
        return results;
    }

    // 단일 언어 SQL Injection 테스트
    async testSingleLanguage(language, server, username, password, mode) {
        try {
            const serverUrl = `http://localhost:${server.port}`;
            const endpoint = `/sql/${mode}/login`;

            const requestData = {
                username: username,
                password: password
            };

            console.log(`🔍 Testing ${language} SQL Injection:`, requestData);

            const response = await fetch(`${serverUrl}${endpoint}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestData)
            });

            const data = await response.json();

            return {
                language: language,
                database: server.database,
                icon: server.icon,
                success: response.ok,
                vulnerabilityDetected: data.data?.vulnerability_detected || data.data?.attack_success || false,
                result: data.data?.result || data.message || 'No result',
                executionTime: data.data?.execution_time || 'N/A',
                payloadUsed: data.data?.payload_used || username,
                mode: mode,
                status: response.status,
                rawResponse: data
            };

        } catch (error) {
            console.error(`❌ Error testing ${language}:`, error);
            return {
                language: language,
                database: server.database,
                icon: server.icon,
                success: false,
                vulnerabilityDetected: false,
                result: `Connection error: ${error.message}`,
                executionTime: 'Error',
                payloadUsed: username,
                mode: mode,
                status: 'error',
                rawResponse: null
            };
        }
    }

    // 결과 표시
    displayResults(results) {
        const resultsSection = document.getElementById('sql-results-section');
        const resultsContent = document.getElementById('sql-results-content');

        if (!results || results.length === 0) {
            resultsSection.style.display = 'none';
            return;
        }

        let html = '';

        results.forEach(result => {
            const statusClass = result.success ?
                (result.vulnerabilityDetected ? 'border-danger' : 'border-success') :
                'border-warning';

            const statusIcon = result.success ?
                (result.vulnerabilityDetected ? 'fas fa-exclamation-triangle text-danger' : 'fas fa-shield-alt text-success') :
                'fas fa-times-circle text-warning';

            const vulnerabilityBadge = result.vulnerabilityDetected ?
                '<span class="badge bg-danger"><i class="fas fa-bug"></i> 취약점 발견</span>' :
                '<span class="badge bg-success"><i class="fas fa-shield-alt"></i> 안전</span>';

            html += `
                <div class="card mb-3 ${statusClass}">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="mb-0">
                                <i class="${statusIcon}"></i>
                                ${result.icon} ${result.language} (${result.database})
                            </h6>
                        </div>
                        <div>
                            ${vulnerabilityBadge}
                            <span class="badge bg-info ms-1">${result.mode}</span>
                        </div>
                    </div>
                    <div class="card-body">
                        <!-- 실행 결과 -->
                        <div class="row mb-3">
                            <div class="col-md-8">
                                <strong>📊 실행 결과:</strong>
                                <div class="bg-light p-2 rounded mt-1">
                                    <code>${result.result}</code>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <small class="text-muted">
                                    <strong>실행 시간:</strong> ${result.executionTime}<br>
                                    <strong>사용된 페이로드:</strong> <code>${result.payloadUsed}</code><br>
                                    <strong>상태:</strong> ${result.status}
                                </small>
                            </div>
                        </div>

                        <!-- 실제 SQL 구문 표시 -->
                        <div class="mt-3">
                            <strong>🔍 실제 실행된 SQL 구문:</strong>
                            <div class="bg-dark text-light p-2 rounded mt-1">
                                <code class="text-warning">${this.generateActualSQL(result.language, result.payloadUsed, result.mode)}</code>
                            </div>
                        </div>

                        <!-- 코드 예시 표시 -->
                        <div class="mt-3">
                            <div class="row">
                                <div class="col-md-6">
                                    <button class="btn btn-sm btn-outline-danger" type="button"
                                            data-bs-toggle="collapse" data-bs-target="#vulnerable-code-${result.language.replace('.', '-')}"
                                            aria-expanded="false">
                                        <i class="fas fa-exclamation-triangle"></i> 취약한 코드 보기
                                    </button>
                                    <div class="collapse mt-2" id="vulnerable-code-${result.language.replace('.', '-')}">
                                        <div class="code-container">
                                            <div class="code-header">
                                                <span class="code-filename">
                                                    <i class="fas fa-file-code"></i>
                                                    vulnerable.${this.getFileExtension(result.language)}
                                                </span>
                                                <span class="vulnerability-badge badge bg-danger">
                                                    <i class="fas fa-exclamation-triangle"></i> 취약점 존재
                                                </span>
                                            </div>
                                            <pre class="line-numbers"><code class="language-${VulnerabilityUtils.getLanguageClass(result.language)}">${this.getVulnerableCode(result.language)}</code></pre>
                                        </div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <button class="btn btn-sm btn-outline-success" type="button"
                                            data-bs-toggle="collapse" data-bs-target="#safe-code-${result.language.replace('.', '-')}"
                                            aria-expanded="false">
                                        <i class="fas fa-shield-alt"></i> 안전한 코드 보기
                                    </button>
                                    <div class="collapse mt-2" id="safe-code-${result.language.replace('.', '-')}">
                                        <div class="code-container">
                                            <div class="code-header">
                                                <span class="code-filename">
                                                    <i class="fas fa-file-code"></i>
                                                    safe.${this.getFileExtension(result.language)}
                                                </span>
                                                <span class="vulnerability-badge badge bg-success">
                                                    <i class="fas fa-shield-alt"></i> 보안 적용
                                                </span>
                                            </div>
                                            <pre class="line-numbers"><code class="language-${VulnerabilityUtils.getLanguageClass(result.language)}">${this.getSafeCode(result.language)}</code></pre>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        ${result.rawResponse ? `
                            <div class="mt-3">
                                <button class="btn btn-sm btn-outline-info" type="button"
                                        data-bs-toggle="collapse" data-bs-target="#raw-${result.language.replace('.', '-')}"
                                        aria-expanded="false">
                                    <i class="fas fa-code"></i> Raw Response
                                </button>
                                <div class="collapse mt-2" id="raw-${result.language.replace('.', '-')}">
                                    <pre class="bg-dark text-light p-2 rounded small">${JSON.stringify(result.rawResponse, null, 2)}</pre>
                                </div>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `;
        });

        resultsContent.innerHTML = html;
        resultsSection.style.display = 'block';

        // 결과 영역으로 스크롤
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    // 언어별 구현 코드 예시 표시
    showImplementationCode(language) {
        const codeExamples = {
            'PHP': {
                vulnerable: `// 취약한 PHP 코드 (MySQL)
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $sql);

if (mysqli_num_rows($result) > 0) {
    echo "로그인 성공!";
} else {
    echo "로그인 실패!";
}`,
                safe: `// 안전한 PHP 코드 (Prepared Statement)
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

if ($stmt->rowCount() > 0) {
    echo "로그인 성공!";
} else {
    echo "로그인 실패!";
}`
            },
            'Node.js': {
                vulnerable: `// 취약한 Node.js 코드 (MongoDB)
const { username, password } = req.body;

// 위험: 직접 쿼리 삽입
const query = {
    username: username,
    password: password
};

const user = await db.collection('users').findOne(query);

if (user) {
    res.json({ success: true, message: "로그인 성공!" });
} else {
    res.json({ success: false, message: "로그인 실패!" });
}`,
                safe: `// 안전한 Node.js 코드 (Input Validation)
const { username, password } = req.body;

// 입력 검증 및 타입 확인
if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Invalid input' });
}

const query = {
    username: { $eq: username },
    password: { $eq: password }
};

const user = await db.collection('users').findOne(query);`
            },
            'Python': {
                vulnerable: `# 취약한 Python 코드 (PostgreSQL)
username = request.json['username']
password = request.json['password']

query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)

result = cursor.fetchone()
if result:
    return {"success": True, "message": "로그인 성공!"}
else:
    return {"success": False, "message": "로그인 실패!"}`,
                safe: `# 안전한 Python 코드 (Parameterized Query)
username = request.json['username']
password = request.json['password']

query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))

result = cursor.fetchone()
if result:
    return {"success": True, "message": "로그인 성공!"}
else:
    return {"success": False, "message": "로그인 실패!"}`
            },
            'Java': {
                vulnerable: `// 취약한 Java 코드 (H2 Database)
String username = request.getParameter("username");
String password = request.getParameter("password");

String sql = "SELECT * FROM users WHERE username = '" + username +
             "' AND password = '" + password + "'";

Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

if (rs.next()) {
    return "로그인 성공!";
} else {
    return "로그인 실패!";
}`,
                safe: `// 안전한 Java 코드 (PreparedStatement)
String username = request.getParameter("username");
String password = request.getParameter("password");

String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);

ResultSet rs = pstmt.executeQuery();

if (rs.next()) {
    return "로그인 성공!";
} else {
    return "로그인 실패!";
}`
            },
            'Go': {
                vulnerable: `// 취약한 Go 코드 (MySQL)
username := c.PostForm("username")
password := c.PostForm("password")

query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s' AND password = '%s'",
                     username, password)

rows, err := db.Query(query)
if err != nil {
    c.JSON(500, gin.H{"error": err.Error()})
    return
}

if rows.Next() {
    c.JSON(200, gin.H{"message": "로그인 성공!"})
} else {
    c.JSON(401, gin.H{"message": "로그인 실패!"})
}`,
                safe: `// 안전한 Go 코드 (Prepared Statement)
username := c.PostForm("username")
password := c.PostForm("password")

query := "SELECT * FROM users WHERE username = ? AND password = ?"
rows, err := db.Query(query, username, password)

if err != nil {
    c.JSON(500, gin.H{"error": err.Error()})
    return
}

if rows.Next() {
    c.JSON(200, gin.H{"message": "로그인 성공!"})
} else {
    c.JSON(401, gin.H{"message": "로그인 실패!"})
}`
            }
        };

        const example = codeExamples[language];
        if (!example) return '';

        return `
            <div class="code-comparison">
                <div class="row">
                    <div class="col-md-6">
                        <h6 class="text-danger"><i class="fas fa-exclamation-triangle"></i> 취약한 코드</h6>
                        <div class="code-section">
                            <pre><code class="language-${VulnerabilityUtils.getLanguageClass(language)}">${example.vulnerable}</code></pre>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <h6 class="text-success"><i class="fas fa-shield-alt"></i> 안전한 코드</h6>
                        <div class="code-section">
                            <pre><code class="language-${VulnerabilityUtils.getLanguageClass(language)}">${example.safe}</code></pre>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // 실제 실행된 SQL 구문 생성
    generateActualSQL(language, payload, mode) {
        const safePayload = payload || 'admin';

        switch (language) {
            case 'PHP':
            case 'Go':
                // MySQL 기반
                return `SELECT * FROM users WHERE username = '${safePayload}' AND password = 'password'`;

            case 'Node.js':
                // MongoDB 기반
                try {
                    const parsedPayload = JSON.parse(safePayload);
                    return `db.users.findOne({ username: ${JSON.stringify(parsedPayload)}, password: "password" })`;
                } catch {
                    return `db.users.findOne({ username: "${safePayload}", password: "password" })`;
                }

            case 'Python':
                // PostgreSQL 기반
                return `SELECT * FROM users WHERE username = '${safePayload}' AND password = 'password'`;

            case 'Java':
                // H2 Database 기반
                return `SELECT * FROM users WHERE username = '${safePayload}' AND password = 'password'`;

            default:
                return `SELECT * FROM users WHERE username = '${safePayload}' AND password = 'password'`;
        }
    }

    // 파일 확장자 반환
    getFileExtension(language) {
        const extensions = {
            'PHP': 'php',
            'Node.js': 'js',
            'Python': 'py',
            'Java': 'java',
            'Go': 'go'
        };
        return extensions[language] || 'txt';
    }

    // 취약한 코드 반환
    getVulnerableCode(language) {
        const codeExamples = this.showImplementationCode(language);
        // HTML에서 취약한 코드 부분만 추출
        const match = codeExamples.match(/vulnerable">(.*?)<\/code>/s);
        if (match) {
            return match[1].replace(/<[^>]*>/g, '').trim();
        }

        // fallback
        switch (language) {
            case 'PHP':
                return `$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
mysqli_query($connection, $sql);`;
            case 'Node.js':
                return `const query = { username: username, password: password };
const user = await db.collection('users').findOne(query);`;
            case 'Python':
                return `query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)`;
            case 'Java':
                return `String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
Statement stmt = connection.createStatement();`;
            case 'Go':
                return `query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s' AND password = '%s'", username, password)
rows, err := db.Query(query)`;
            default:
                return '// 취약한 코드 예시가 없습니다.';
        }
    }

    // 안전한 코드 반환
    getSafeCode(language) {
        const codeExamples = this.showImplementationCode(language);
        // HTML에서 안전한 코드 부분만 추출
        const match = codeExamples.match(/safe">(.*?)<\/code>/s);
        if (match) {
            return match[1].replace(/<[^>]*>/g, '').trim();
        }

        // fallback
        switch (language) {
            case 'PHP':
                return `$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);`;
            case 'Node.js':
                return `const query = {
    username: { $eq: username },
    password: { $eq: password }
};
const user = await db.collection('users').findOne(query);`;
            case 'Python':
                return `query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))`;
            case 'Java':
                return `String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);`;
            case 'Go':
                return `query := "SELECT * FROM users WHERE username = ? AND password = ?"
rows, err := db.Query(query, username, password)`;
            default:
                return '// 안전한 코드 예시가 없습니다.';
        }
    }

    // 결과 초기화
    clearResults() {
        const resultsSection = document.getElementById('sql-results-section');
        const resultsContent = document.getElementById('sql-results-content');

        resultsSection.style.display = 'none';
        resultsContent.innerHTML = '';
        this.results = {};

        VulnerabilityUtils.showSuccessAlert('🧹 SQL Injection 테스트 결과가 초기화되었습니다!');
    }

    // 폼 제출 이벤트 핸들러 등록
    initializeEventHandlers() {
        const form = document.getElementById('sql-injection-form');
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();

                const username = document.getElementById('sql-username').value;
                const password = document.getElementById('sql-password').value;
                const mode = document.getElementById('sql-test-mode').value;
                const targetLanguage = document.getElementById('sql-target-language').value;

                if (!username.trim()) {
                    VulnerabilityUtils.showErrorAlert('사용자명을 입력해주세요!');
                    return;
                }

                try {
                    await this.executeSQLTest(username, password, mode, targetLanguage);
                    VulnerabilityUtils.showSuccessAlert('🎯 SQL Injection 테스트가 완료되었습니다!');
                } catch (error) {
                    console.error('SQL Injection test error:', error);
                    VulnerabilityUtils.showErrorAlert(`테스트 중 오류가 발생했습니다: ${error.message}`);
                }
            });
        }
    }
}

// 전역 인스턴스 생성
export const sqlInjectionModule = new SQLInjectionModule();