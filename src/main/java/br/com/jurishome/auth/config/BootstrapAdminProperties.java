package br.com.jurishome.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("app.bootstrap-admin")
public record BootstrapAdminProperties(String username, String email, String password) {
    public boolean isComplete() {
        return username != null && !username.isBlank()
            && email != null && !email.isBlank()
            && password != null && !password.isBlank();
    }
}
