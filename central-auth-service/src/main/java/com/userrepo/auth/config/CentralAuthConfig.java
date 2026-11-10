package com.userrepo.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Activates the {@link AppProperties} configuration-properties binding. */
@Configuration
@EnableConfigurationProperties(AppProperties.class)
public class CentralAuthConfig {
}
