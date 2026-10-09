package br.com.jurishome.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import br.com.jurishome.auth.security.LoginFailureHandler;
import br.com.jurishome.auth.security.LoginSuccessHandler;
import br.com.jurishome.auth.security.TwoFactorAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    AuthenticationProvider authenticationProvider(
        UserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setHideUserNotFoundExceptions(true);
        return provider;
    }

    @Bean
    SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        AuthenticationProvider provider,
        LoginSuccessHandler successHandler,
        LoginFailureHandler failureHandler,
        TwoFactorAuthenticationFilter twoFactorFilter
    ) throws Exception {
        http
            .authenticationProvider(provider)
            // As permissoes sao verificadas no servidor, mesmo quando um link nao aparece na interface.
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/", "/login", "/cadastro", "/cadastro/pendente", "/cadastro/confirmar",
                    "/cadastro/reenviar", "/senha/esqueci", "/senha/redefinir",
                    "/css/**", "/images/**", "/error"
                ).permitAll()
                .requestMatchers("/2fa/**").authenticated()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/moderador/**").hasAnyRole("MODERATOR", "ADMIN")
                .requestMatchers("/usuario/**").hasAnyRole("USER", "MODERATOR", "ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .deleteCookies("SESSION", "JSESSIONID")
            )
            .sessionManagement(session -> session
                .sessionFixation(fixation -> fixation.migrateSession())
            )
            .headers(headers -> headers
                .contentSecurityPolicy(csp -> csp.policyDirectives(
                    "default-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
                ))
                .referrerPolicy(referrer -> referrer.policy(
                    ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN
                ))
            )
            .exceptionHandling(exceptions -> exceptions
                .accessDeniedPage("/acesso-negado")
            )
            .addFilterAfter(twoFactorFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
