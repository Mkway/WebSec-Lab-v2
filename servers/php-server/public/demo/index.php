<?php
/**
 * XSS 데모 페이지 - 실제 XSS 실행 환경
 */

$scenario = $_GET['scenario'] ?? 'basic';
$payload = $_GET['payload'] ?? '';
$mode = $_GET['mode'] ?? 'vulnerable';

?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS 데모 - <?= ucfirst($scenario) ?></title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .demo-container {
            min-height: 400px;
            border: 2px dashed #dee2e6;
            padding: 20px;
            margin: 20px 0;
            background: #f8f9fa;
        }
        .vulnerable { border-color: #dc3545; background: #f8d7da; }
        .safe { border-color: #28a745; background: #d4edda; }
        .payload-info {
            font-family: monospace;
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 15px;
        }
        .execution-result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            background: white;
            border: 1px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container mt-4">
        <div class="row">
            <div class="col-12">
                <div class="alert alert-<?= $mode === 'vulnerable' ? 'danger' : 'success' ?>">
                    <h4>
                        <i class="fas fa-<?= $mode === 'vulnerable' ? 'bug' : 'shield-alt' ?>"></i>
                        <?= $mode === 'vulnerable' ? '취약한' : '안전한' ?> 코드 실행
                    </h4>
                    <p class="mb-0">시나리오: <strong><?= ucfirst($scenario) ?></strong></p>
                </div>

                <?php if ($payload): ?>
                <div class="payload-info">
                    <strong>입력된 페이로드:</strong><br>
                    <?= htmlspecialchars($payload) ?>
                </div>
                <?php endif; ?>

                <div class="demo-container <?= $mode === 'vulnerable' ? 'vulnerable' : 'safe' ?>">
                    <h5>실행 결과:</h5>

                    <?php
                    switch ($scenario) {
                        case 'basic':
                            echo "<div class='execution-result'>";
                            echo "<h6>기본 출력 결과:</h6>";
                            if ($mode === 'vulnerable') {
                                // 취약한 코드 - XSS가 실제로 실행됨
                                echo "<p>입력하신 내용: " . $payload . "</p>";
                            } else {
                                // 안전한 코드 - HTML 이스케이프
                                echo "<p>입력하신 내용: " . htmlspecialchars($payload) . "</p>";
                            }
                            echo "</div>";
                            break;

                        case 'search':
                            echo "<div class='execution-result'>";
                            echo "<h6>검색 결과:</h6>";
                            if ($mode === 'vulnerable') {
                                echo "<p>'" . $payload . "'에 대한 검색 결과를 찾을 수 없습니다.</p>";
                            } else {
                                echo "<p>'" . htmlspecialchars($payload) . "'에 대한 검색 결과를 찾을 수 없습니다.</p>";
                            }
                            echo "</div>";
                            break;

                        case 'greeting':
                            echo "<div class='execution-result'>";
                            echo "<h6>사용자 인사말:</h6>";
                            if ($mode === 'vulnerable') {
                                echo "<h4>안녕하세요, " . $payload . "님!</h4>";
                            } else {
                                echo "<h4>안녕하세요, " . htmlspecialchars($payload) . "님!</h4>";
                            }
                            echo "</div>";
                            break;

                        case 'form':
                            echo "<div class='execution-result'>";
                            echo "<h6>폼 처리 결과:</h6>";
                            if ($mode === 'vulnerable') {
                                echo "<div class='alert alert-info'>폼이 성공적으로 제출되었습니다: " . $payload . "</div>";
                            } else {
                                echo "<div class='alert alert-info'>폼이 성공적으로 제출되었습니다: " . htmlspecialchars($payload) . "</div>";
                            }
                            echo "</div>";
                            break;

                        default:
                            echo "<p>알 수 없는 시나리오입니다.</p>";
                    }
                    ?>
                </div>

                <div class="mt-4">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h6>XSS 탐지 상태</h6>
                                </div>
                                <div class="card-body">
                                    <?php
                                    $xss_detected = false;
                                    if ($mode === 'vulnerable' && $payload) {
                                        // XSS 패턴 탐지
                                        $patterns = [
                                            '/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/mi',
                                            '/<iframe\b[^>]*>/i',
                                            '/javascript:/i',
                                            '/on\w+\s*=/i'
                                        ];

                                        foreach ($patterns as $pattern) {
                                            if (preg_match($pattern, $payload)) {
                                                $xss_detected = true;
                                                break;
                                            }
                                        }
                                    }
                                    ?>

                                    <div class="d-flex align-items-center">
                                        <?php if ($xss_detected): ?>
                                            <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                            <span class="text-danger">XSS 공격 탐지됨!</span>
                                        <?php else: ?>
                                            <i class="fas fa-check-circle text-success me-2"></i>
                                            <span class="text-success">안전한 상태</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card">
                                <div class="card-header">
                                    <h6>보안 권장사항</h6>
                                </div>
                                <div class="card-body">
                                    <?php if ($mode === 'vulnerable'): ?>
                                        <ul class="mb-0">
                                            <li>입력값 검증 필요</li>
                                            <li>HTML 이스케이프 적용</li>
                                            <li>CSP 헤더 설정</li>
                                        </ul>
                                    <?php else: ?>
                                        <ul class="mb-0">
                                            <li>✅ HTML 이스케이프 적용됨</li>
                                            <li>✅ 입력값 안전하게 처리됨</li>
                                            <li>✅ XSS 공격 차단됨</li>
                                        </ul>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- 실시간 XSS 실행 확인 -->
                <div class="mt-4">
                    <div class="alert alert-warning">
                        <h6><i class="fas fa-info-circle"></i> 실행 확인</h6>
                        <p class="mb-0">
                            <?php if ($mode === 'vulnerable' && $xss_detected): ?>
                                이 페이지에서 XSS 스크립트가 실제로 실행됩니다. 개발자 도구의 콘솔을 확인하거나 알림창을 확인해보세요.
                            <?php else: ?>
                                이 페이지에서는 XSS 스크립트가 실행되지 않습니다. 입력값이 안전하게 처리되었습니다.
                            <?php endif; ?>
                        </p>
                    </div>
                </div>

                <!-- 테스트 링크들 -->
                <div class="mt-4">
                    <h6>빠른 테스트:</h6>
                    <div class="btn-group mb-2" role="group">
                        <a href="?scenario=<?= $scenario ?>&mode=vulnerable&payload=<?= urlencode('<script>alert("XSS Alert!")</script>') ?>"
                           class="btn btn-danger btn-sm">취약한 버전</a>
                        <a href="?scenario=<?= $scenario ?>&mode=safe&payload=<?= urlencode('<script>alert("XSS Alert!")</script>') ?>"
                           class="btn btn-success btn-sm">안전한 버전</a>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>

    <!-- XSS 실행 감지 스크립트 -->
    <script>
        // XSS 실행 여부를 부모 창에 알림
        if (window.parent && window.parent !== window) {
            const xssDetected = <?= $xss_detected ? 'true' : 'false' ?>;
            const mode = '<?= $mode ?>';

            window.parent.postMessage({
                type: 'xss_result',
                detected: xssDetected,
                mode: mode,
                executed: xssDetected && mode === 'vulnerable'
            }, '*');
        }

        // XSS 실행 추적을 위한 글로벌 함수
        window.xssExecuted = function(message) {
            console.log('XSS Executed:', message);
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({
                    type: 'xss_executed',
                    message: message
                }, '*');
            }
        };
    </script>
</body>
</html>