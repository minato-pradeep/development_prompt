package com.userrepo.auth.sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Sample microservice that validates JWTs issued by central-auth-service.
 * Demonstrates JWKS-based signature verification with issuer + audience checks.
 * See SecurityConfig and SampleController for the integration pattern.
 */
@SpringBootApplication
public class SampleResourceServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(SampleResourceServerApplication.class, args);
    }
}
