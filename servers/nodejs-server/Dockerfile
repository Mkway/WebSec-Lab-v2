FROM node:18-alpine

# 시스템 패키지 업데이트 및 필수 패키지 설치
RUN apk update && apk add --no-cache \
    git \
    curl \
    python3 \
    make \
    g++ \
    mysql-client \
    postgresql-client

# 작업 디렉토리 설정
WORKDIR /app

# package.json과 package-lock.json 복사 (캐시 최적화)
COPY package*.json ./

# 의존성 설치
RUN npm install --only=production

# 애플리케이션 파일 복사
COPY . .

# 사용자 생성 및 권한 설정
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001 && \
    chown -R nodejs:nodejs /app

USER nodejs

# 포트 노출
EXPOSE 3000

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# 시작 명령
CMD ["npm", "start"]