# MANUAL CHANGES NEEDED

This document lists every place where Docker, a local PostgreSQL, environment
variables, a real Microsoft Entra tenant, or other external infrastructure is
required to complete the setup and run the integration tests.

The project compiles and all 53 unit tests pass without any of the items below.
Apply each item before attempting end-to-end testing.

---

## 1. Java 25 Runtime

**Status:** Already installed at `D:\tools\jdk-25.0.5+8`.

For Maven builds set:
```powershell
$env:JAVA_HOME = 'D:\tools\jdk-25.0.5+8'
$env:Path      = "$env:JAVA_HOME\bin;$env:Path"
mvn ...
```

---

## 2. PostgreSQL database

The service requires PostgreSQL 14 or later.

### Option A — Docker Compose (recommended for local dev)

```bash
# Copy .env.example to .env and fill in the values, then:
docker compose up -d
```

### Option B — Local PostgreSQL installation

1. Install PostgreSQL from https://www.postgresql.org/download/windows/
2. Create the database:
   ```sql
   CREATE DATABASE central_auth_db;
   ```
3. Run the provisioning script as a superuser to create the application role:
   ```bash
   psql -U postgres -d central_auth_db -f docs/db-provisioning.sql
   ```
4. Flyway migrations run automatically on startup.

---

## 3. Required environment variables

Set these before starting the service. **Never commit real values.**

| Variable | Purpose | Example |
|----------|---------|---------|
| `CENTRAL_AUTH_DB_URL` | JDBC URL (app role) | `jdbc:postgresql://localhost:5432/central_auth_db` |
| `CENTRAL_AUTH_DB_APP_USER` | App DB role (no BYPASSRLS) | `central_auth_app` |
| `CENTRAL_AUTH_DB_APP_PASSWORD` | App role password | *(from your DB)* |
| `CENTRAL_AUTH_DB_MIGRATION_URL` | JDBC URL (migration role) | *(same URL)* |
| `CENTRAL_AUTH_DB_MIGRATION_USER` | Migration role (schema owner) | `central_auth_owner` |
| `CENTRAL_AUTH_DB_MIGRATION_PASSWORD` | Migration role password | *(from your DB)* |
| `CENTRAL_AUTH_BOOTSTRAP_SECRET` | One-time Super Admin bootstrap secret (**min 16 chars**) | *(generate: `openssl rand -base64 24`)* |
| `CENTRAL_AUTH_TOTP_MASTER_KEY` | AES-256 master key for TOTP secrets at rest (base64 32 bytes) | *(generate: `openssl rand -base64 32`)* |
| `CENTRAL_AUTH_TOTP_MASTER_KID` | Key ID for the master key | `prod-key-2026-01` |

### Generate AES-256 master key (PowerShell):
```powershell
$bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
[System.Convert]::ToBase64String($bytes)
```

---

## 4. Docker Desktop (for Testcontainers integration tests)

Install Docker Desktop from https://www.docker.com/products/docker-desktop/

After installation and reboot, verify:
```bash
docker --version
docker compose version
```

### Running integration tests (require Docker + PostgreSQL):

```bash
# From the project root
mvn -B verify
# Or target specific integration tests:
mvn -B test -Dtest="*IntegrationTest"
```

### Testcontainers module names (Spring Boot 4 / Testcontainers 2.0.x)

**Important:** Testcontainers 2.0 renamed its modules. The correct artifact names (already in pom.xml) are:
- `testcontainers-postgresql` (NOT `postgresql`)
- `testcontainers-junit-jupiter` (NOT `junit-jupiter`)

---

## 5. Flyway — privileged migration role

Flyway must connect with a role that owns the schema (not the app role) to:
- Create tables
- Enable Row-Level Security (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY`)
- Create RLS policies (`CREATE POLICY ...`)

The app role (`central_auth_app`) does NOT have these privileges.

In `application.yml` the migration credentials are separate:
```yaml
spring.flyway.user:     ${CENTRAL_AUTH_DB_MIGRATION_USER}
spring.flyway.password: ${CENTRAL_AUTH_DB_MIGRATION_PASSWORD}
```

---

## 6. PostgreSQL Row-Level Security — verification

After Flyway migrations run, verify RLS is active:
```sql
-- Connect as the APP ROLE (central_auth_app), not the owner.
SET LOCAL app.company_id = '00000000-0000-0000-0000-000000000000';
SELECT * FROM companies;  -- should return 0 rows (no matching company_id)

-- Connect as the OWNER role — BYPASSRLS applies, sees all rows.
SELECT * FROM companies;  -- returns all rows
```

Expected: the app role sees only rows matching `app.company_id`.

---

## 7. Microsoft Entra ID (SSO integration)

The Microsoft SSO integration is fully implemented in `MicrosoftSsoService` but
requires real Azure credentials to run the OIDC exchange. Without them, the
callback throws `INTERNAL_ERROR` with a clear message.

### Steps to enable:

1. Register an app in Microsoft Entra ID (Azure Portal → App registrations).
2. Note: **Tenant ID**, **Client ID**, **Client Secret**.
3. Add the callback redirect URI: `http://localhost:8081/api/v1/auth/microsoft/callback`.
4. Create a company SSO configuration via Super Admin:
   ```http
   POST /api/v1/platform/companies/{id}/auth-settings
   ```
   or directly update `microsoft_sso_settings` in the DB.
5. Set `client_secret_ref` to a secret manager reference (never the plaintext secret).
   For development, you may set it to the plaintext only in a local `.env` and read it
   in `MicrosoftSsoService.exchangeCodeAndValidate()`.

### Live tests that require real Entra credentials (Section 23):

- Test 14: Microsoft SSO login works with a valid identity mapping
- Test 15: Microsoft SSO rejects wrong tenants and unlinked identities
- Test 26: Break-glass admin login when MICROSOFT_SSO is selected

These tests are correctly written but will throw `INTERNAL_ERROR` until real
credentials are supplied via the steps above.

### Completing `exchangeCodeAndValidate()`:

In `MicrosoftSsoService`, replace the `throw` stub with a real implementation:
```java
private JWTClaimsSet exchangeCodeAndValidate(String code, MicrosoftSsoSettings cfg,
                                              String nonce, String ipAddress) {
    // 1. POST to https://login.microsoftonline.com/{tid}/oauth2/v2.0/token
    //    with: code, redirect_uri, client_id, client_secret, code_verifier
    // 2. Fetch JWKS from https://login.microsoftonline.com/{tid}/discovery/v2.0/keys
    // 3. Validate id_token: signature, iss, aud, exp, nonce, tid
    // 4. Return the validated JWTClaimsSet
}
```

The PKCE, state, identity-mapping, assurance-level, and token-exchange logic is
fully implemented — only the Entra HTTP exchange is stubbed.

---

## 8. Signing key management in production

In development, the service generates an ephemeral ES256 keypair at startup and
keeps the private key in memory. Tokens from previous runs cannot be validated
after a restart.

For production:
1. Generate a persistent EC P-256 keypair and store it in a keystore or Vault.
2. Inject the private key into the service via environment or mounted secret.
3. Update `SigningKeysService.init()` to load the key from the store instead of
   generating a new one on each startup.
4. The public key is already persisted in `signing_keys_metadata` on first startup.

---

## 9. TOTP master key rotation

The `AesGcmEncryptor` uses a single master key (`CENTRAL_AUTH_TOTP_MASTER_KEY`).
To rotate:
1. Generate a new key, assign a new `CENTRAL_AUTH_TOTP_MASTER_KID`.
2. Add logic to `AesGcmEncryptor` to look up the old key by `encryption_kid`
   (stored alongside each encrypted TOTP secret in the DB).
3. Re-encrypt existing TOTP secrets with the new key on a background job.

---

## 10. Email/SMS notification channel

`DevNotificationService` logs a safe placeholder. For production:
1. Implement `NotificationService` with a real SMTP client (Spring Mail) or SMS provider.
2. Mark it `@Primary` and inject SMTP credentials from environment variables.
3. The dev stub can be kept as `@Profile("dev")`.

---

## 11. Logo storage

Logos are stored in a local directory (`./storage/logos` by default, overridden
via `app.logo.storage-path`). For production with multiple instances:
1. Implement an S3-compatible storage adapter.
2. Replace `LogoStorageService.store()` and `load()` to use the S3 SDK.
3. The public path reference in `company_logos.stored_path` stays the same.

---

## 12. Running all 35 integration test scenarios (Section 23)

Once Docker + PostgreSQL + environment variables are configured:

```bash
# Full test run including Testcontainers integration tests:
mvn -B verify

# Specific test scenario by number:
mvn -B test -Dtest="TenantAuthServiceTest#test_3_cannotBypassPasswordChange"
```

### Tests that require Docker (Testcontainers):
All tests that start or use `@Testcontainers` annotation and the
`testcontainers-postgresql` module.

### Tests that require real Microsoft Entra credentials (Section 23 items 14, 15, 26):
These are annotated `@Disabled("Requires real Entra credentials — see MANUAL_CHANGES_NEEDED.md")`
in the integration test class. Remove the annotation and supply credentials to run them.

---

## 13. Mockito + Java 25 warning

You will see:
```
Mockito is currently self-attaching to enable the inline-mock-maker.
This will no longer work in future releases of the JDK.
```

This is a **warning only**, not a test failure. To suppress it, add the Mockito
agent to the Surefire plugin in `pom.xml`:
```xml
<plugin>
  <groupId>org.apache.maven.plugins</groupId>
  <artifactId>maven-surefire-plugin</artifactId>
  <configuration>
    <argLine>-javaagent:${settings.localRepository}/org/mockito/mockito-core/...jar</argLine>
  </configuration>
</plugin>
```

---

## 14. Production checklist

- [ ] All environment variables set (Section 3 above)
- [ ] PostgreSQL provisioned with the app role (no BYPASSRLS)
- [ ] Flyway migrations ran successfully (`mvn flyway:info`)
- [ ] Bootstrap Super Admin created (check logs for "bootstrap complete")
- [ ] TOTP master key set (persistent AES-256 key, not ephemeral)
- [ ] JWT signing key loaded from keystore/Vault (not ephemeral)
- [ ] HTTPS configured (reverse proxy or TLS termination)
- [ ] CORS origins restricted to your actual frontend domains
- [ ] Email/SMS notification channel implemented and tested
- [ ] Microsoft Entra SSO configured (if using MICROSOFT_SSO login method)
- [ ] Rate-limit counters backed by PostgreSQL (default) — do NOT switch to in-memory
- [ ] Docker image built and tested: `docker build -t central-auth-service .`
- [ ] Logo storage mounted to a persistent volume or S3
- [ ] Audit log table is INSERT-only for the app role (enforced in `db-provisioning.sql`)
