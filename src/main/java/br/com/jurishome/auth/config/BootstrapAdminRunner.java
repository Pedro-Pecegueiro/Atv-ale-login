package br.com.jurishome.auth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import br.com.jurishome.auth.service.UserAccountService;

@Component
public class BootstrapAdminRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapAdminRunner.class);
    private final BootstrapAdminProperties properties;
    private final UserAccountService userService;

    public BootstrapAdminRunner(BootstrapAdminProperties properties, UserAccountService userService) {
        this.properties = properties;
        this.userService = userService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.isComplete()) {
            log.info("Bootstrap de administrador ignorado: variaveis ADMIN_* nao foram informadas.");
            return;
        }
        userService.createBootstrapAdmin(properties.username(), properties.email(), properties.password());
        log.info("Conta administrativa inicial verificada para o usuario '{}'.", properties.username());
    }
}
