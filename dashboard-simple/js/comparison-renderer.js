// 취약점 비교 분석 렌더러 클래스
class ComparisonRenderer {

    // 메인 비교 렌더링 함수
    static render(vulnerableResult, safeResult) {
        const { vulnerability } = vulnerableResult;

        switch (vulnerability) {
            case 'sql-injection':
                return this.renderSQLComparison(vulnerableResult, safeResult);
            case 'xss':
                return this.renderXSSComparison(vulnerableResult, safeResult);
            default:
                return `<div>알 수 없는 취약점 유형: ${vulnerability}</div>`;
        }
    }

    // SQL Injection 비교 렌더링
    static renderSQLComparison(vulnerableResult, safeResult) {
        const server = SERVERS[vulnerableResult.language];

        // 공격 성공 여부 분석
        const vulnerableAttack = vulnerableResult.data?.result?.authentication_bypassed ||
                                vulnerableResult.data?.success === true;
        const safeAttack = safeResult.data?.result?.authentication_bypassed ||
                          safeResult.data?.success === true;

        return `
            <div class="comparison-container">
                <!-- 비교 개요 -->
                <div class="comparison-overview">
                    <h2>💉 SQL Injection 비교 분석</h2>
                    <div class="attack-summary">
                        <div class="summary-item vulnerable-summary">
                            <span class="status-icon">${vulnerableAttack ? '⚠️' : '✅'}</span>
                            <span class="status-text">취약한 코드: ${vulnerableAttack ? '공격 성공' : '공격 실패'}</span>
                        </div>
                        <div class="summary-item safe-summary">
                            <span class="status-icon">${safeAttack ? '⚠️' : '✅'}</span>
                            <span class="status-text">안전한 코드: ${safeAttack ? '공격 성공' : '공격 차단'}</span>
                        </div>
                    </div>
                </div>

                <!-- 코드 비교 섹션 -->
                <div class="code-comparison">
                    <div class="comparison-side vulnerable-side">
                        <h3>🚨 취약한 코드</h3>
                        <div class="code-block">
                            <pre><code class="language-php">// 취약한 로그인 코드
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users
          WHERE username = '$username'
          AND password = '$password'";

$result = mysqli_query($connection, $query);

if (mysqli_num_rows($result) > 0) {
    echo "로그인 성공!";
} else {
    echo "로그인 실패!";
}</code></pre>
                        </div>

                        <div class="execution-result vulnerable-result">
                            <h4>🔍 실행 결과</h4>
                            <div class="result-data">
                                <div class="query-info">
                                    <strong>실제 실행된 쿼리:</strong>
                                    <div class="query-display">
                                        SELECT * FROM users WHERE username = '${vulnerableResult.requestData.username}' AND password = '${vulnerableResult.requestData.password}'
                                    </div>
                                </div>
                                <div class="attack-result ${vulnerableAttack ? 'attack-success' : 'attack-fail'}">
                                    ${vulnerableAttack ?
                                        '⚠️ <strong>인증 우회 성공!</strong> OR 조건으로 인해 항상 TRUE가 되어 로그인됩니다.' :
                                        '✅ 공격이 실패했습니다.'
                                    }
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="comparison-side safe-side">
                        <h3>🛡️ 안전한 코드</h3>
                        <div class="code-block">
                            <pre><code class="language-php">// 안전한 로그인 코드 (Prepared Statement)
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $pdo->prepare("SELECT * FROM users
                       WHERE username = ?
                       AND password = ?");

$stmt->execute([$username, $password]);

if ($stmt->rowCount() > 0) {
    echo "로그인 성공!";
} else {
    echo "로그인 실패!";
}</code></pre>
                        </div>

                        <div class="execution-result safe-result">
                            <h4>🔍 실행 결과</h4>
                            <div class="result-data">
                                <div class="query-info">
                                    <strong>안전하게 처리된 쿼리:</strong>
                                    <div class="query-display">
                                        SELECT * FROM users WHERE username = ? AND password = ?
                                        <br><small>파라미터가 안전하게 바인딩되어 SQL 인젝션이 불가능합니다.</small>
                                    </div>
                                </div>
                                <div class="attack-result ${safeAttack ? 'attack-success' : 'attack-fail'}">
                                    ${safeAttack ?
                                        '⚠️ 예상치 못한 문제가 발생했습니다.' :
                                        '✅ <strong>공격 차단 성공!</strong> 입력값이 문자열로만 처리되어 SQL 인젝션이 무효화되었습니다.'
                                    }
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 학습 포인트 -->
                <div class="learning-points">
                    <h3>📚 학습 포인트</h3>
                    <div class="learning-grid">
                        <div class="learning-item">
                            <h4>🔍 취약점의 원인</h4>
                            <p>사용자 입력을 SQL 쿼리에 <strong>직접 연결</strong>하여 발생합니다. 공격자가 SQL 문법을 삽입하여 쿼리 로직을 변경할 수 있습니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>🛡️ 해결 방법</h4>
                            <p><strong>Prepared Statement</strong>를 사용하여 SQL과 데이터를 분리합니다. 이렇게 하면 입력값이 SQL 명령어가 아닌 단순 데이터로만 처리됩니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>⚠️ 공격의 위험성</h4>
                            <p>인증 우회, 데이터 탈취, 데이터베이스 조작, 시스템 침해까지 가능한 <strong>매우 위험한</strong> 취약점입니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>🎯 예방책</h4>
                            <p>입력값 검증, ORM 사용, 최소 권한 원칙, 정기적인 보안 감사를 통해 예방할 수 있습니다.</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // XSS 비교 렌더링
    static renderXSSComparison(vulnerableResult, safeResult) {
        const server = SERVERS[vulnerableResult.language];

        // 공격 성공 여부 분석
        const vulnerableXSS = vulnerableResult.data?.result?.xss_detected;
        const safeXSS = safeResult.data?.result?.xss_detected;

        const vulnerableOutput = vulnerableResult.data?.result?.html_output || '';
        const safeOutput = safeResult.data?.result?.html_output || '';

        return `
            <div class="comparison-container">
                <!-- 비교 개요 -->
                <div class="comparison-overview">
                    <h2>🔥 Cross-Site Scripting (XSS) 비교 분석</h2>
                    <div class="attack-summary">
                        <div class="summary-item vulnerable-summary">
                            <span class="status-icon">${vulnerableXSS ? '⚠️' : '✅'}</span>
                            <span class="status-text">취약한 코드: ${vulnerableXSS ? 'XSS 실행됨' : 'XSS 차단됨'}</span>
                        </div>
                        <div class="summary-item safe-summary">
                            <span class="status-icon">${safeXSS ? '⚠️' : '✅'}</span>
                            <span class="status-text">안전한 코드: ${safeXSS ? 'XSS 실행됨' : 'XSS 차단됨'}</span>
                        </div>
                    </div>
                </div>

                <!-- 코드 비교 섹션 -->
                <div class="code-comparison">
                    <div class="comparison-side vulnerable-side">
                        <h3>🚨 취약한 코드</h3>
                        <div class="code-block">
                            <pre><code class="language-php">// 취약한 검색 결과 출력
$search_query = $_GET['q'];

echo "&lt;div class='result'&gt;";
echo "검색 결과: " . $search_query;
echo "&lt;/div&gt;";</code></pre>
                        </div>

                        <div class="execution-result vulnerable-result">
                            <h4>🔍 실행 결과</h4>
                            <div class="result-data">
                                <div class="html-output">
                                    <strong>생성된 HTML:</strong>
                                    <div class="html-display vulnerable-html">
                                        ${vulnerableOutput}
                                    </div>
                                </div>
                                <div class="attack-result ${vulnerableXSS ? 'attack-success' : 'attack-fail'}">
                                    ${vulnerableXSS ?
                                        '⚠️ <strong>XSS 공격 성공!</strong> 스크립트가 브라우저에서 실행됩니다.' :
                                        '✅ XSS 공격이 실패했습니다.'
                                    }
                                </div>
                                ${vulnerableXSS ? `
                                    <div class="xss-demo">
                                        <button onclick="VulnerabilityRenderer.executeXSS('${vulnerableResult.requestData.payload.replace(/'/g, "\\'")}')">
                                            ⚡ 실제 XSS 실행해보기
                                        </button>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    </div>

                    <div class="comparison-side safe-side">
                        <h3>🛡️ 안전한 코드</h3>
                        <div class="code-block">
                            <pre><code class="language-php">// 안전한 검색 결과 출력 (HTML 이스케이프)
$search_query = $_GET['q'];

echo "&lt;div class='result'&gt;";
echo "검색 결과: " . htmlspecialchars($search_query, ENT_QUOTES, 'UTF-8');
echo "&lt;/div&gt;";</code></pre>
                        </div>

                        <div class="execution-result safe-result">
                            <h4>🔍 실행 결과</h4>
                            <div class="result-data">
                                <div class="html-output">
                                    <strong>생성된 HTML:</strong>
                                    <div class="html-display safe-html">
                                        ${safeOutput}
                                    </div>
                                </div>
                                <div class="attack-result ${safeXSS ? 'attack-success' : 'attack-fail'}">
                                    ${safeXSS ?
                                        '⚠️ 예상치 못한 문제가 발생했습니다.' :
                                        '✅ <strong>XSS 차단 성공!</strong> HTML 특수문자가 안전하게 이스케이프되었습니다.'
                                    }
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 학습 포인트 -->
                <div class="learning-points">
                    <h3>📚 학습 포인트</h3>
                    <div class="learning-grid">
                        <div class="learning-item">
                            <h4>🔍 취약점의 원인</h4>
                            <p>사용자 입력을 <strong>HTML로 직접 출력</strong>하여 발생합니다. 악성 스크립트가 브라우저에서 실행될 수 있습니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>🛡️ 해결 방법</h4>
                            <p><strong>HTML 이스케이프</strong>를 사용하여 특수문자를 안전한 형태로 변환합니다. &lt;, &gt;, &amp;, " 등이 안전하게 처리됩니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>⚠️ 공격의 위험성</h4>
                            <p>세션 탈취, 키로깅, 피싱, 악성 코드 유포 등 <strong>사용자를 직접 공격</strong>할 수 있는 위험한 취약점입니다.</p>
                        </div>
                        <div class="learning-item">
                            <h4>🎯 예방책</h4>
                            <p>출력 인코딩, CSP 헤더, 입력값 검증, 안전한 템플릿 엔진 사용으로 예방할 수 있습니다.</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }
}