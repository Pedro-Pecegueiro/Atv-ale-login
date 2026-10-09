package br.com.jurishome.auth.security;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import br.com.jurishome.auth.service.TwoFactorService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final TwoFactorService twoFactorService;

    public LoginSuccessHandler(TwoFactorService twoFactorService) {
        this.twoFactorService = twoFactorService;
    }

    @Override
    public void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException, ServletException {
        request.getSession().setAttribute(TwoFactorSession.VERIFIED, false);
        String target = twoFactorService.isEnabled(authentication.getName())
            ? "/2fa/verificar"
            : "/2fa/configurar";
        response.sendRedirect(request.getContextPath() + target);
    }
}
