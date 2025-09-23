FROM golang:1.21-alpine AS builder

# 시스템 패키지 설치
RUN apk add --no-cache git gcc musl-dev

# 작업 디렉토리 설정
WORKDIR /app

# Go 모듈 파일 복사 및 의존성 다운로드 (캐시 최적화)
COPY go.mod go.sum ./
RUN go mod download

# 애플리케이션 소스 복사
COPY . .

# 애플리케이션 빌드
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main ./src

# ===== 프로덕션 이미지 =====
FROM alpine:latest

# 시스템 패키지 설치
RUN apk --no-cache add ca-certificates mysql-client postgresql-client curl

# 작업 디렉토리 설정
WORKDIR /root/

# 빌드된 바이너리 복사
COPY --from=builder /app/main .

# 사용자 생성 및 권한 설정
RUN adduser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /root

USER appuser

# 포트 노출
EXPOSE 8080

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# 시작 명령
CMD ["./main"]