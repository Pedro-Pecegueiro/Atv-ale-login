package br.com.jurishome.auth.config;

import java.net.URI;
import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.password-reset")
public record PasswordResetProperties(
    Delivery delivery,
    String baseUrl,
    Duration tokenDuration,
    String from
) {
    public PasswordResetProperties {
        if (delivery == null) {
            throw new IllegalArgumentException("PASSWORD_RESET_DELIVERY deve ser screen ou smtp.");
        }
        if (!isHttpBaseUrl(baseUrl)) {
            throw new IllegalArgumentException("APP_BASE_URL deve ser uma URL HTTP ou HTTPS valida.");
        }
        if (tokenDuration == null || tokenDuration.isZero() || tokenDuration.isNegative()) {
            throw new IllegalArgumentException("PASSWORD_RESET_TOKEN_DURATION deve ser uma duracao positiva.");
        }
        if (delivery == Delivery.SMTP && (from == null || from.isBlank())) {
            throw new IllegalArgumentException("MAIL_FROM deve ser informado para entrega SMTP.");
        }
        if (delivery == Delivery.SCREEN && !isLoopback(baseUrl)) {
            throw new IllegalArgumentException(
                "PASSWORD_RESET_DELIVERY=screen so pode ser usado com APP_BASE_URL local. Use smtp fora do ambiente local."
            );
        }
    }

    public enum Delivery {
        SCREEN,
        SMTP
    }

    private static boolean isLoopback(String baseUrl) {
        try {
            String host = URI.create(baseUrl).getHost();
            return "localhost".equalsIgnoreCase(host)
                || "127.0.0.1".equals(host)
                || "::1".equals(host)
                || "0:0:0:0:0:0:0:1".equals(host);
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private static boolean isHttpBaseUrl(String baseUrl) {
        try {
            URI uri = URI.create(baseUrl);
            return uri.getHost() != null
                && ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()));
        } catch (IllegalArgumentException | NullPointerException ex) {
            return false;
        }
    }
}
