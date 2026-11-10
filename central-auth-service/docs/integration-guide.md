# Integration Guide — Central Authentication Service

## Overview

Other microservices validate access tokens issued by this service. This guide
documents every integration pattern and the token freshness policy (Section 14).

---

## 1. Token validation (normal requests)

For most requests: local validation only, no network call to this service.

**Steps:**
1. Fetch JWKS from `GET /.well-known/jwks.json` once at startup. Cache it.
2. On each request, extract the `kid` from the JWT header.
3. Look up the public key in the cached JWKS. If unknown, re-fetch once.
4. Verify the ES256 signature.
5. Validate `iss` = `{central-auth.issuer}` (configured per environment).
6. Validate `aud` = your service's expected audience string.
7. Validate `exp` has not passed.
8. Extract `company_id`, `roles`, `permissions`, `ver` from claims.

**Spring Boot example:**
```yaml
spring.security.oauth2.resourceserver.jwt:
  jwk-set-uri: http://central-auth-service:8081/.well-known/jwks.json
  issuer-uri:  http://central-auth-service:8081
```

See `samples/resource-server-example/` for a complete working example.

---

## 2. Token freshness policy (Section 14)

Access tokens live at most **15 minutes**. Changes to user/company/role take
effect within that window via the `ver` claim:

| Event | Effect |
|-------|--------|
| User deactivated | Refresh token revoked immediately; access token expires within 15 min |
| User status/role change | `session_version` incremented; old `ver` returns `active=false` |
| Company deactivated | All refresh tokens revoked immediately |
| Password reset | All sessions revoked |

---

## 3. Sensitive operations — mandatory introspection

The following operations **MUST** call introspection. Do not rely on local
validation alone:

- Role assignment / permission changes
- Password reset
- Authentication setting changes
- Financial approvals (PURCHASE_APPROVE)
- Any action with audit / compliance requirements

**Introspection call:**
```http
POST /api/v1/oauth/introspect
Authorization: Bearer <your-service-client-token>
Content-Type: application/x-www-form-urlencoded

token=<user-access-token>
```

Response:
```json
{ "active": true, "sub": "...", "company_id": "...", "roles": [...] }
{ "active": false }
```

`active: false` means the token is expired, revoked, or stale (ver mismatch).
Reject the request and return 401.

---

## 4. Service-to-service authentication (Section 14)

Each consuming microservice has a dedicated `service_client` registered by
Super Admin. Use OAuth 2.0 client credentials to obtain a service token:

```http
POST /api/v1/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_SECRET
```

Service tokens carry `roles: ["SERVICE_CLIENT"]` and explicit scopes.
They do not carry a `company_id`; scope is enforced by your service.

---

## 5. Client types and PKCE (Section 30)

| Client type | How to authenticate |
|-------------|---------------------|
| WEB | Standard login or Microsoft SSO + PKCE |
| DESKTOP | Login + PKCE (loopback redirect) |
| MOBILE_IOS / MOBILE_ANDROID | Login + PKCE (Universal Links / App Links) |
| SERVICE | Client credentials |

All public clients (desktop, mobile) **must** use PKCE S256. Plain PKCE is rejected.

For Microsoft SSO on native clients:
1. Open system browser to GET `/api/v1/auth/microsoft/authorize?companyCode=X&clientId=Y`
2. Entra redirects to the callback; callback issues a single-use internal code.
3. POST `/api/v1/auth/microsoft/token-exchange?code=X&codeVerifier=Y&clientId=Z`
4. Receive internal access + refresh tokens.

---

## 6. Token storage guidance (Section 30.7)

| Client | Access token | Refresh token |
|--------|-------------|---------------|
| Browser SPA | Memory only | Backend-for-frontend (HttpOnly cookie) preferred |
| Mobile | Memory | Keychain (iOS) or Keystore-backed storage (Android) |
| Desktop | Memory | OS credential store |

Never store refresh tokens in localStorage, plain files or shared preferences.

---

## 7. Registering a new permission

New microservices register their permissions via Super Admin:
```http
POST /api/v1/platform/permissions
Authorization: Bearer <super-admin-token>
Content-Type: application/json

{
  "resource": "INVOICE",
  "action": "APPROVE",
  "description": "Approve an invoice",
  "registeredBy": "invoice-service"
}
```

Companies then include the permission in their roles via
`PUT /api/v1/roles/{id}/permissions`.
