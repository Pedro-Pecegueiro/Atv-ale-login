package br.com.jurishome.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.theme")
public record ThemeProperties(String name, String displayName) {
}
