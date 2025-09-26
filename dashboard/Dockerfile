# 기존 Nginx 이미지 사용 (Docker Hub 문제 회피)
FROM nginx:1.25-alpine

# 시스템 업데이트 및 curl 설치
RUN apk update && apk add --no-cache curl && rm -rf /var/cache/apk/*

# Nginx 설정 파일 복사
COPY nginx.conf /etc/nginx/conf.d/default.conf


# 포트 노출
EXPOSE 80

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/ || exit 1

# Nginx 시작
CMD ["nginx", "-g", "daemon off;"]