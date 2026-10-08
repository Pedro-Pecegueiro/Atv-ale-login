package br.com.jurishome.auth.security;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import br.com.jurishome.auth.service.UserAccountService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final UserAccountService userService;

    public LoginFailureHandler(UserAccountService userService) {
        super("/login?error");
        this.userService = userService;
    }

    @Override
    public void onAuthenticationFailure(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException exception
    ) throws IOException, ServletException {
        userService.recordLoginFailure(request.getParameter("username"));
        super.onAuthenticationFailure(request, response, exception);
    }
}
