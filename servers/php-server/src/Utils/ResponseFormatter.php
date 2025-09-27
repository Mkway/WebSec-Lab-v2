<?php

namespace WebSecLab\Utils;

class ResponseFormatter
{
    public static function success(array $data, array $metadata = []): string
    {
        $response = [
            'success' => true,
            'data' => $data,
            'metadata' => array_merge([
                'language' => 'php',
                'timestamp' => date('c')
            ], $metadata)
        ];

        return json_encode($response, JSON_PRETTY_PRINT);
    }

    public static function error(string $message, int $code = 400, array $metadata = []): string
    {
        $response = [
            'success' => false,
            'data' => [
                'error' => $message,
                'code' => $code
            ],
            'metadata' => array_merge([
                'language' => 'php',
                'timestamp' => date('c')
            ], $metadata)
        ];

        return json_encode($response, JSON_PRETTY_PRINT);
    }

    public static function vulnerability(
        string $result,
        bool $vulnerabilityDetected,
        string $payloadUsed,
        bool $attackSuccess,
        string $executionTime,
        string $vulnerabilityType,
        string $mode = 'vulnerable'
    ): string {
        $data = [
            'result' => $result,
            'vulnerability_detected' => $vulnerabilityDetected,
            'payload_used' => $payloadUsed,
            'attack_success' => $attackSuccess,
            'execution_time' => $executionTime
        ];

        $metadata = [
            'language' => 'php',
            'vulnerability_type' => $vulnerabilityType,
            'mode' => $mode,
            'timestamp' => date('c')
        ];

        return self::success($data, $metadata);
    }
}