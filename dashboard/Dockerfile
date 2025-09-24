FROM nginx:alpine

# 시스템 패키지 업데이트
RUN apk update && apk add --no-cache \
    curl \
    && rm -rf /var/cache/apk/*

# Nginx 설정
COPY nginx.conf /etc/nginx/conf.d/default.conf

# 웹 파일 복사
COPY public/ /usr/share/nginx/html/
COPY assets/ /usr/share/nginx/html/assets/
COPY components/ /usr/share/nginx/html/components/

# 포트 노출
EXPOSE 80

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/ || exit 1

# Nginx 시작
CMD ["nginx", "-g", "daemon off;"]