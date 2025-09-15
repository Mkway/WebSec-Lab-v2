<?php

namespace WebSecLab\Controllers;

use WebSecLab\Utils\DatabaseManager;

/**
 * Health Controller
 * 서버 상태 체크를 위한 컨트롤러
 */
class HealthController extends BaseController
{
    /**
     * 서버 헬스체크
     */
    public function check(): string
    {
        $health = [
            'status' => 'healthy',
            'server' => 'PHP',
            'version' => PHP_VERSION,
            'timestamp' => date('c'),
            'uptime' => $this->getUptime(),
            'memory_usage' => $this->getMemoryUsage(),
            'checks' => []
        ];

        // 데이터베이스 연결 체크
        try {
            $db = DatabaseManager::getInstance();
            $health['checks']['database'] = [
                'status' => 'healthy',
                'connection' => 'active',
                'driver' => 'mysql'
            ];
        } catch (\Exception $e) {
            $health['checks']['database'] = [
                'status' => 'unhealthy',
                'error' => $e->getMessage()
            ];
            $health['status'] = 'degraded';
        }

        // Redis 연결 체크
        try {
            if (extension_loaded('redis')) {
                $redis = new \Redis();
                $redis->connect($_ENV['REDIS_HOST'] ?? 'redis', 6379);
                $redis->ping();
                $health['checks']['redis'] = [
                    'status' => 'healthy',
                    'connection' => 'active'
                ];
                $redis->close();
            } else {
                $health['checks']['redis'] = [
                    'status' => 'not_available',
                    'message' => 'Redis extension not loaded'
                ];
            }
        } catch (\Exception $e) {
            $health['checks']['redis'] = [
                'status' => 'unhealthy',
                'error' => $e->getMessage()
            ];
        }

        // 디스크 공간 체크
        $health['checks']['disk_space'] = $this->getDiskSpace();

        // 확장 모듈 체크
        $health['checks']['extensions'] = $this->getExtensions();

        return $this->jsonResponse($health);
    }

    /**
     * 서버 업타임 조회
     */
    private function getUptime(): array
    {
        $uptime = file_get_contents('/proc/uptime');
        $uptimeSeconds = floatval(explode(' ', $uptime)[0]);
        
        return [
            'seconds' => $uptimeSeconds,
            'formatted' => $this->formatUptime($uptimeSeconds)
        ];
    }

    /**
     * 메모리 사용량 조회
     */
    private function getMemoryUsage(): array
    {
        return [
            'current' => memory_get_usage(true),
            'peak' => memory_get_peak_usage(true),
            'limit' => ini_get('memory_limit'),
            'formatted' => [
                'current' => $this->formatBytes(memory_get_usage(true)),
                'peak' => $this->formatBytes(memory_get_peak_usage(true))
            ]
        ];
    }

    /**
     * 디스크 공간 체크
     */
    private function getDiskSpace(): array
    {
        $totalBytes = disk_total_space('.');
        $freeBytes = disk_free_space('.');
        $usedBytes = $totalBytes - $freeBytes;
        $usagePercent = round(($usedBytes / $totalBytes) * 100, 2);

        return [
            'total' => $totalBytes,
            'free' => $freeBytes,
            'used' => $usedBytes,
            'usage_percent' => $usagePercent,
            'status' => $usagePercent > 90 ? 'critical' : ($usagePercent > 80 ? 'warning' : 'healthy'),
            'formatted' => [
                'total' => $this->formatBytes($totalBytes),
                'free' => $this->formatBytes($freeBytes),
                'used' => $this->formatBytes($usedBytes)
            ]
        ];
    }

    /**
     * 로드된 확장 모듈 체크
     */
    private function getExtensions(): array
    {
        $requiredExtensions = ['pdo', 'pdo_mysql', 'mysqli', 'curl', 'json', 'mbstring'];
        $optionalExtensions = ['redis', 'xdebug', 'gd', 'zip'];
        
        $extensions = [
            'required' => [],
            'optional' => []
        ];

        foreach ($requiredExtensions as $ext) {
            $extensions['required'][$ext] = extension_loaded($ext);
        }

        foreach ($optionalExtensions as $ext) {
            $extensions['optional'][$ext] = extension_loaded($ext);
        }

        return $extensions;
    }

    /**
     * 업타임 포맷팅
     */
    private function formatUptime(float $seconds): string
    {
        $days = floor($seconds / 86400);
        $hours = floor(($seconds % 86400) / 3600);
        $minutes = floor(($seconds % 3600) / 60);
        
        return sprintf('%dd %dh %dm', $days, $hours, $minutes);
    }

    /**
     * 바이트 단위 포맷팅
     */
    private function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= pow(1024, $pow);
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }
}