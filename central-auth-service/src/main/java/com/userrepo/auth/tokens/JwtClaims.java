package com.userrepo.auth.tokens;

/**
 * Custom JWT claim names (Section 13, 30.6). Standard claims (sub, iss, aud,
 * iat, exp, jti, auth_time) use Nimbus constants; these are service-specific.
 */
public final class JwtClaims {

    private JwtClaims() {
    }

    /** Subject's company UUID (tenant context). Absent for platform tokens. */
    public static final String COMPANY_ID = "company_id";
    public static final String COMPANY_CODE = "company_code";
    public static final String ROLES = "roles";
    /** Permissions, or a permission reference when the set is large (Section 13). */
    public static final String PERMISSIONS = "permissions";
    /** Authentication methods used (e.g. ["pwd","otp"]). */
    public static final String AMR = "amr";
    /** Time of authentication (seconds since epoch). */
    public static final String AUTH_TIME = "auth_time";
    /** Session id. */
    public static final String SID = "sid";
    /** Session version at issuance; staleness is detected via introspection (Section 14). */
    public static final String VER = "ver";
    /** Authorized party / client_id (Section 30.6). */
    public static final String AZP = "azp";
    /** Token type hint. */
    public static final String TYP = "typ";

    public static final String TYP_ACCESS = "at+jwt";
    public static final String TYP_REFRESH = "rt+jwt";
}
