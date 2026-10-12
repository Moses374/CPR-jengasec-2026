# syntax=docker/dockerfile:1
# Build:  docker buildx build --platform linux/amd64 -t ghcr.io/<owner>/cpr-jengasec-2026:v1 .

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S -G app -H -s /sbin/nologin app
WORKDIR /app
COPY --from=build --chown=app:app /src/target/app.jar /app/app.jar

# 2 CPU / 3 GB is shared with the database: keep the JVM well inside its share and
# exit (so the platform restarts it) rather than limp on after an OutOfMemoryError.
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=50 -XX:+ExitOnOutOfMemoryError -Djava.io.tmpdir=/tmp"

USER app
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
