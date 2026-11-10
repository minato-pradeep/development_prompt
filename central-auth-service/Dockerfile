# =============================================================================
# Multi-stage Docker build for central-auth-service
# See MANUAL_CHANGES_NEEDED.md — you must supply environment variables before
# running this container in production.
# =============================================================================

# Stage 1 — build
FROM eclipse-temurin:25-jdk-noble AS builder
WORKDIR /workspace

COPY pom.xml .
# Cache dependencies in a separate layer
RUN mvn -B dependency:go-offline -q 2>/dev/null || true

COPY src ./src
RUN mvn -B package -DskipTests -q

# Stage 2 — runtime (JRE only)
FROM eclipse-temurin:25-jre-noble AS runtime
WORKDIR /app

# Non-root user for the application process.
RUN groupadd -r authsvc && useradd -r -g authsvc authsvc

COPY --from=builder /workspace/target/central-auth-service-*.jar app.jar

# Private logo storage directory (override with S3 in production).
RUN mkdir -p /app/storage/logos && chown authsvc:authsvc /app/storage/logos

USER authsvc

EXPOSE 8081

# Healthcheck — calls the actuator health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -sf http://localhost:8081/actuator/health || exit 1

ENTRYPOINT ["java", \
    "-XX:+UseContainerSupport", \
    "-XX:MaxRAMPercentage=75", \
    "-jar", "app.jar"]
