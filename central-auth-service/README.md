# Central Authentication Service

Multi-Tenant Central Authentication, SSO and User Repository Microservice.

A centralized identity repository for multiple companies (tenants). Provides authentication,
RBAC, company management, TOTP (RFC 6238), Microsoft Entra ID single sign-on (OIDC + PKCE),
and JWT (ES256) token issuance/validation for other microservices.

**Backend REST APIs only.** No Angular, React, HTML, CSS, JSP or any frontend application.

---

## Technology stack and verified versions

Every dependency below was verified against Maven Central and the Spring Boot 4.1.2 BOM
(`spring-boot-dependencies-4.1.2`). Versions managed by the BOM are not pinned in `pom.xml`
(they inherit from Boot); the README states them explicitly as required by the prompt.

| Component | Version | Managed by | Verification |
|-----------|---------|------------|--------------|
| Language / runtime | Java 25 LTS (Temurin 25.0.5) | local install | `java -version` |
| Framework | Spring Boot 4.1.2 | parent POM | Maven Central GA release |
| Spring Framework | 7.x (>= 7.0.10) | Boot BOM | Boot 4.1.2 requires Framework 7.0.10+ |
| Spring Security | 7.x | Boot BOM | via Boot 4.1.2 |
| Security / JWT | Spring Security OAuth2 Resource Server + Nimbus JOSE | Boot BOM | starter + transitive Nimbus |
| Database | PostgreSQL (with Row-Level Security) | external | infra |
| ORM | Spring Data JPA / Hibernate 7.4.13.Final | Boot BOM | `hibernate.version` in BOM |
| Bean Validation | Jakarta Validation 3.1.1 | Boot BOM | `jakarta-validation.version` |
| Persistence API | Jakarta Persistence 3.2.0 | Boot BOM | `jakarta-persistence.version` |
| Servlet API | Jakarta Servlet 6.1.0 | Boot BOM | `jakarta-servlet.version` |
| Migrations | Flyway 12.4.0 | Boot BOM | `flyway.version` in BOM |
| JSON | Jackson 3.1.7 (`tools.jackson`, primary) + Jackson 2.21.7 (compat) | Boot BOM | `jackson-bom.version` / `jackson-2-bom.version` |
| Token format | JWT signed with ES256 (ECDSA P-256 SHA-256) | Nimbus | — |
| Password hashing | Argon2id (Bouncy Castle `Argon2BytesGenerator`) | pinned | bcprov-jdk18on 1.86 |
| TOTP | RFC 6238 (HMAC-SHA1, 6 digits, 30s) | pinned | java-otp 1.0.0 |
| Microsoft SSO | Microsoft Entra ID, OpenID Connect | Nimbus + RestClient | — |
| API docs | OpenAPI 3 / Swagger UI | pinned | springdoc-openapi-starter-webmvc-ui 3.2.0 |
| Build | Maven 3.9.15 | local | `mvn -version` |
| Testing | JUnit 5, Mockito, Testcontainers (PostgreSQL) | Boot BOM | testcontainers via Boot BOM |
| Dev DB | H2 2.4.240 (optional, non-RLS unit tests) | Boot BOM | `h2.version` |

### Spring Boot 4 modular starters used

The prompt requires Boot 4 modular starters (not Boot 3 snippets). The following starters were
confirmed present in the Spring Boot 4.1.2 BOM and are used in `pom.xml`:

- `spring-boot-starter-webmvc` (replaces Boot 3 `spring-boot-starter-web`)
- `spring-boot-starter-data-jpa`
- `spring-boot-starter-validation`
- `spring-boot-starter-jdbc`
- `spring-boot-starter-flyway` (dedicated Flyway starter)
- `spring-boot-starter-security`
- `spring-boot-starter-security-oauth2-resource-server` (Boot 4 modular OAuth2 starter)
- `spring-boot-starter-actuator`
- `spring-boot-starter-test`
- `spring-boot-starter-security-oauth2-resource-server-test` (test)

### Compatibility rule applied

Verified that springdoc-openapi (3.2.0), Testcontainers (Boot-managed), Flyway (12.4.0 via the
dedicated Boot 4 starter + `flyway-database-postgresql`), and the Argon2/TOTP libraries have
releases compatible with Spring Boot 4 / Spring Framework 7 / Jackson 3. No Spring Boot 3 snippets
are used; stable versions only.

---

## Configuration

| Property | Value |
|----------|-------|
| Application name | `central-auth-service` |
| Port | `8081` |
| Database | `central_auth_db` |
| API base path | `/api/v1` |
| Base package | `com.userrepo.auth` |

### Required environment variables / secrets (never committed)

- `CENTRAL_AUTH_DB_URL`, `CENTRAL_AUTH_DB_APP_USER`, `CENTRAL_AUTH_DB_APP_PASSWORD` — app DB role (no `BYPASSRLS`)
- `CENTRAL_AUTH_DB_MIGRATION_URL`, `CENTRAL_AUTH_DB_MIGRATION_USER`, `CENTRAL_AUTH_DB_MIGRATION_PASSWORD` — privileged migration role
- `CENTRAL_AUTH_BOOTSTRAP_SECRET` — one-time Super Admin bootstrap secret (disabled after first enrollment)
- `CENTRAL_AUTH_TOTP_MASTER_KEY`, `CENTRAL_AUTH_TOTP_MASTER_KID` — master key for AES-GCM encryption of TOTP secrets at rest
- JWT ES256 signing private key — keystore / Vault / cloud KMS (see `signing_keys_metadata`)

---

## Build and run

```bash
# Compile (uses Java 25)
mvn -q compile

# Package
mvn -q package

# Run (requires a reachable PostgreSQL with the app + migration roles configured)
mvn spring-boot:run
```

> **Note:** Integration tests that rely on Testcontainers (PostgreSQL) require Docker to run.
> See `MANUAL_CHANGES_NEEDED.md` for how to run them locally. The project compiles and its unit
> tests run without Docker.

---

## Project structure

Feature-module layout. Each module owns its entities, repositories, services and controllers.

```
central-auth-service/
├── pom.xml
├── Dockerfile
├── compose.yaml
├── README.md
├── MANUAL_CHANGES_NEEDED.md
├── src/
│   ├── main/
│   │   ├── java/com/userrepo/auth/
│   │   │   ├── CentralAuthApplication.java
│   │   │   ├── config/
│   │   │   ├── security/
│   │   │   ├── platform/
│   │   │   ├── company/
│   │   │   ├── users/
│   │   │   ├── roles/
│   │   │   ├── permissions/
│   │   │   ├── authentication/
│   │   │   ├── totp/
│   │   │   ├── microsoft/
│   │   │   ├── tokens/
│   │   │   ├── notification/
│   │   │   ├── audit/
│   │   │   ├── exception/
│   │   │   └── common/
│   │   └── resources/
│   │       ├── application.yml
│   │       └── db/migration/
│   └── test/
├── docs/
│   ├── architecture.md
│   ├── api-documentation.md
│   ├── database-design.md
│   ├── security-design.md
│   └── integration-guide.md
├── samples/resource-server-example/
└── postman/
```

---

## Implementation status

The service is implemented phase by phase, each phase ending with a working build gate
(compiles, Flyway migrations apply on a clean PostgreSQL Testcontainer, listed tests pass).
See the task tracking for current phase status.
