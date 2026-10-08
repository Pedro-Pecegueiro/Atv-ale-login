package br.com.jurishome.auth.web;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import br.com.jurishome.auth.config.ThemeProperties;

@ControllerAdvice
public class GlobalViewAdvice {

    private final ThemeProperties theme;

    public GlobalViewAdvice(ThemeProperties theme) {
        this.theme = theme;
    }

    @ModelAttribute("themeName")
    public String themeName() {
        String configured = theme.name();
        return configured != null && configured.matches("[a-z0-9-]+") ? configured : "default";
    }

    @ModelAttribute("appName")
    public String appName() {
        return theme.displayName();
    }
}
