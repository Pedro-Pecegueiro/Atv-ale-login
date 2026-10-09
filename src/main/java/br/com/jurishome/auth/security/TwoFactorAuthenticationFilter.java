package br.com.jurishome.auth.security;

import java.io.IOException;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.jurishome.auth.service.TwoFactorService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class TwoFactorAuthenticationFilter extends OncePerRequestFilter {

    private final TwoFactorService twoFactorService;

    public TwoFactorAuthenticationFilter(TwoFactorService twoFactorService) {
        this.twoFactorService = twoFactorService;
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!isPasswordAuthenticated(authentication) || isAllowedPath(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        HttpSession session = request.getSession(false);
        if (session != null && Boolean.TRUE.equals(session.getAttribute(TwoFactorSession.VERIFIED))) {
            filterChain.doFilter(request, response);
            return;
        }

        // A senha sozinha não libera as áreas protegidas; o segundo fator conclui a autenticação.
        String target = twoFactorService.isEnabled(authentication.getName())
            ? "/2fa/verificar"
            : "/2fa/configurar";
        response.sendRedirect(request.getContextPath() + target);
    }

    private boolean isPasswordAuthenticated(Authentication authentication) {
        return authentication != null
            && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken);
    }

    private boolean isAllowedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String contextPath = request.getContextPath();
        String path = contextPath.isEmpty() ? uri : uri.substring(contextPath.length());
        return path.startsWith("/2fa/")
            || path.equals("/logout")
            || path.equals("/error")
            || path.equals("/favicon.ico")
            || path.startsWith("/css/")
            || path.startsWith("/images/");
    }
}
