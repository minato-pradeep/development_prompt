package com.userrepo.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Multi-Tenant Central Authentication, SSO and User Repository Microservice.
 *
 * <p>This service is the central identity repository and authentication authority for multiple
 * companies (tenants). It provides authentication, RBAC, company management, TOTP (RFC 6238),
 * Microsoft Entra ID single sign-on (OIDC + PKCE) and JWT (ES256) token issuance/validation for
 * other microservices.
 *
 * <p>Backend REST APIs only. No frontend is provided by this service.
 */
@SpringBootApplication
public class CentralAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(CentralAuthApplication.class, args);
    }
}
