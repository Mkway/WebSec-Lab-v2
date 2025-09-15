FROM openjdk:17-jdk-slim

# 시스템 패키지 업데이트 및 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    git \
    curl \
    maven \
    default-mysql-client \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Maven Wrapper 설치
RUN curl -o /tmp/maven-wrapper.tar.gz \
    https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.2.0/maven-wrapper-3.2.0.tar.gz && \
    tar -xzf /tmp/maven-wrapper.tar.gz -C /tmp && \
    rm /tmp/maven-wrapper.tar.gz

# 작업 디렉토리 설정
WORKDIR /app

# pom.xml 복사 및 의존성 다운로드 (캐시 최적화)
COPY pom.xml ./
COPY mvnw ./
COPY .mvn ./.mvn
RUN chmod +x mvnw
RUN ./mvnw dependency:go-offline -B

# 애플리케이션 소스 복사
COPY src ./src

# 애플리케이션 빌드
RUN ./mvnw clean package -DskipTests

# 사용자 생성 및 권한 설정
RUN adduser --disabled-password --gecos '' appuser && \
    chown -R appuser:appuser /app

USER appuser

# 포트 노출
EXPOSE 8080 5005

# 헬스체크
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

# JVM 메모리 설정
ENV JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC"

# 시작 명령
CMD ["java", "-jar", "target/websec-java-server.jar"]