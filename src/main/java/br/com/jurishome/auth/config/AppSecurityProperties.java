package br.com.jurishome.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.security")
public record AppSecurityProperties(int maxFailedAttempts, Duration lockDuration) {
    public AppSecurityProperties {
        if (maxFailedAttempts < 1) {
            throw new IllegalArgumentException("MAX_FAILED_ATTEMPTS deve ser maior que zero.");
        }
        if (lockDuration == null || lockDuration.isZero() || lockDuration.isNegative()) {
            throw new IllegalArgumentException("LOCK_DURATION deve ser uma duracao positiva.");
        }
    }
}
