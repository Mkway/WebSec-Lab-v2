FROM php:8.2-apache

# 시스템 패키지 업데이트 및 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    libzip-dev \
    zip \
    unzip \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# PHP 확장 모듈 설치
RUN docker-php-ext-install pdo_mysql mbstring exif pcntl bcmath gd zip

# Redis 확장 설치
RUN pecl install redis && docker-php-ext-enable redis

# Xdebug 설치 (개발 환경용)
RUN pecl install xdebug && docker-php-ext-enable xdebug

# Apache 모듈 활성화
RUN a2enmod rewrite headers

# Composer 설치
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# 작업 디렉토리 설정
WORKDIR /var/www/html

# Apache 설정
COPY ./apache.conf /etc/apache2/sites-available/000-default.conf

# PHP 설정
COPY ./php.ini /usr/local/etc/php/conf.d/custom.ini

# 포트 노출
EXPOSE 80

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost/health || exit 1

# 시작 명령
CMD ["apache2-foreground"]