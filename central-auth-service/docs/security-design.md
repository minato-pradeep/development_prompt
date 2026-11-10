# Security Design

## Cryptography

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Password hashing | Argon2id | 65536 KiB memory, 3 iterations, parallelism 1, 16-byte salt, 32-byte hash |
| JWT signing | ES256 (ECDSA P-256) | Keys rotated per startup; 24h overlap window; kid in header |
| TOTP | HMAC-SHA1, RFC 6238 | 6 digits, 30s, ±1 step tolerance |
| TOTP secret storage | AES-256-GCM | 96-bit nonce, 128-bit tag; key from env/KMS |
| Refresh tokens | SHA-256 hash stored | Opaque 256-bit random; rotated on every use |

## Multi-tenancy isolation

1. Application layer: every query scoped by `company_id` extracted from the authenticated JWT.
2. Database layer: PostgreSQL Row-Level Security on all tenant-scoped tables, keyed on
   `SET LOCAL app.company_id = '<uuid>'` set before any query.
3. Composite FK enforcement prevents cross-tenant references.
4. The app role (`central_auth_app`) does NOT have `BYPASSRLS`.
5. Platform Super Admin queries use `SET LOCAL app.platform_context = 'true'` and a
   separate DB code path.

## Token freshness (ver claim)

Every user and company has a `session_version` counter. On sensitive changes
(status, role, password) the counter increments. The `ver` claim in the JWT
records the version at issuance. Introspection compares `ver` to the current
value and returns `active: false` when stale.

## Break-glass access

Company Admins always retain a local password + TOTP login even when the company
uses `MICROSOFT_SSO`. Break-glass use is audited and raises an alert record.

## Signing key management

Private keys are generated in memory (dev) or loaded from a keystore/Vault/KMS
(production — see MANUAL_CHANGES_NEEDED.md). Public keys are persisted in
`signing_keys_metadata` and served via JWKS. Old keys are retired with a 24-hour
overlap window so already-issued tokens remain verifiable.

## OWASP ASVS alignment

- V2: Authentication — Argon2id, account lockout, TOTP, MFA for admins
- V3: Session Management — sid claim, session_version, refresh token rotation
- V4: Access Control — RBAC, privilege escalation protection, cross-tenant denial
- V6: Stored Cryptography — AES-GCM for secrets, hashed tokens
- V9: Communications — HTTPS enforced in deployed environments
- V10: Malicious Code — input validation, parameterized queries via JPA
