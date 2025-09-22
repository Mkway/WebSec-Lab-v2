<?php

namespace WebSecLab\Vulnerabilities\XSS;

/**
 * XSS 취약점 전용 인터페이스
 * 모든 XSS 유형의 공통 구조 정의
 */
interface XSSInterface
{
    /**
     * 취약한 XSS 코드 실행
     *
     * @param string $payload XSS 페이로드
     * @param array $context 실행 컨텍스트 (form, url, cookie 등)
     * @return array 실행 결과
     */
    public function executeVulnerable(string $payload, array $context = []): array;

    /**
     * 안전한 코드 실행 (XSS 방어)
     *
     * @param string $payload XSS 페이로드
     * @param array $context 실행 컨텍스트
     * @return array 실행 결과
     */
    public function executeSafe(string $payload, array $context = []): array;

    /**
     * XSS 페이로드 탐지
     *
     * @param string $input 입력 데이터
     * @return bool XSS 위험성 여부
     */
    public function detectXSS(string $input): bool;

    /**
     * 테스트용 기본 페이로드 목록
     *
     * @return array 페이로드 배열
     */
    public function getTestPayloads(): array;

    /**
     * XSS 유형 반환
     *
     * @return string reflected, stored, dom
     */
    public function getXSSType(): string;
}