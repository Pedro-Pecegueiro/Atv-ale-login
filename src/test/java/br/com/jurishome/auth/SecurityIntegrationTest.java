package br.com.jurishome.auth;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.EnumSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import br.com.jurishome.auth.domain.Role;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.repository.UserAccountRepository;
import br.com.jurishome.auth.repository.EmailVerificationTokenRepository;
import br.com.jurishome.auth.repository.PasswordResetTokenRepository;
import br.com.jurishome.auth.service.UserSessionService;
import br.com.jurishome.auth.service.TotpService;
import jakarta.servlet.http.Cookie;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIntegrationTest {

    private static final String PASSWORD = "Senha-Forte-2026!";
    private static final String USERNAME = "security-test-user";
    private static final String MODERATOR = "security-test-moderator";
    private static final String ADMIN = "security-test-admin";
    private static final String REGISTERED = "security-test-register";
    private static final String UNCONFIGURED = "security-test-unconfigured";
    private static final String TOTP_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private UserAccountRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private UserSessionService userSessionService;
    @Autowired
    private TotpService totpService;
    @Autowired
    private EmailVerificationTokenRepository verificationTokenRepository;
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @AfterEach
    void cleanUp() {
        removeTestAccount(USERNAME);
        removeTestAccount(MODERATOR);
        removeTestAccount(ADMIN);
        removeTestAccount(REGISTERED);
        removeTestAccount(UNCONFIGURED);
    }

    @Test
    void anonymousUserIsRedirectedToLogin() throws Exception {
        mockMvc.perform(get("/dashboard"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login"));
    }

    @Test
    void publicPagesReturnSecurityHeaders() throws Exception {
        mockMvc.perform(get("/login"))
            .andExpect(status().isOk())
            .andExpect(header().string("X-Content-Type-Options", "nosniff"))
            .andExpect(header().string("X-Frame-Options", "DENY"))
            .andExpect(header().string(
                "Content-Security-Policy",
                "default-src 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'"
            ));
    }

    @Test
    void loginErrorDoesNotRevealAccountState() throws Exception {
        MvcResult result = mockMvc.perform(get("/login?error"))
            .andExpect(status().isOk())
            .andReturn();

        assertThat(result.getResponse().getContentAsString())
            .contains("Credenciais inválidas.")
            .doesNotContain("conta inativa")
            .doesNotContain("temporariamente bloqueada");
    }

    @Test
    void userCanAccessUserAreaButNotModeratorOrAdminAreas() throws Exception {
        Cookie sessionCookie = login(createAccount(USERNAME, Role.ROLE_USER));

        mockMvc.perform(get("/dashboard").cookie(sessionCookie))
            .andExpect(status().isOk())
            .andExpect(view().name("dashboard"));
        mockMvc.perform(get("/usuario").cookie(sessionCookie))
            .andExpect(status().isOk())
            .andExpect(view().name("areas/user"));
        mockMvc.perform(get("/moderador").cookie(sessionCookie))
            .andExpect(status().isForbidden());
        mockMvc.perform(get("/admin/usuarios").cookie(sessionCookie))
            .andExpect(status().isForbidden());
    }

    @Test
    void moderatorCanAccessModeratorAreaButNotAdminArea() throws Exception {
        Cookie sessionCookie = login(createAccount(MODERATOR, Role.ROLE_MODERATOR));

        mockMvc.perform(get("/moderador").cookie(sessionCookie))
            .andExpect(status().isOk())
            .andExpect(view().name("areas/moderator"));
        mockMvc.perform(get("/admin/usuarios").cookie(sessionCookie))
            .andExpect(status().isForbidden());
    }

    @Test
    void administratorCanAccessUserManagement() throws Exception {
        Cookie sessionCookie = login(createAccount(ADMIN, Role.ROLE_ADMIN));

        mockMvc.perform(get("/admin/usuarios").cookie(sessionCookie))
            .andExpect(status().isOk())
            .andExpect(view().name("admin/users"));
    }

    @Test
    void passwordAuthenticationRequiresTheAuthenticatorCode() throws Exception {
        String username = createAccount(USERNAME, Role.ROLE_USER);

        MvcResult passwordResult = mockMvc.perform(formLogin("/login").user(username).password(PASSWORD))
            .andExpect(authenticated().withUsername(username))
            .andExpect(redirectedUrl("/2fa/verificar"))
            .andReturn();
        Cookie passwordSession = passwordResult.getResponse().getCookie("SESSION");

        mockMvc.perform(get("/dashboard").cookie(passwordSession))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/2fa/verificar"));
    }

    @Test
    void firstLoginRequiresAuthenticatorEnrollmentAndGeneratesQrCode() throws Exception {
        createAccount(UNCONFIGURED, Role.ROLE_USER);
        UserAccount account = userRepository.findByUsername(UNCONFIGURED).orElseThrow();
        account.setTwoFactorEnabled(false);
        account.setTotpSecret(null);
        userRepository.save(account);

        MvcResult passwordResult = mockMvc.perform(formLogin("/login").user(UNCONFIGURED).password(PASSWORD))
            .andExpect(authenticated().withUsername(UNCONFIGURED))
            .andExpect(redirectedUrl("/2fa/configurar"))
            .andReturn();
        Cookie passwordSession = passwordResult.getResponse().getCookie("SESSION");

        mockMvc.perform(get("/2fa/configurar").cookie(passwordSession))
            .andExpect(status().isOk())
            .andExpect(view().name("auth/two-factor-setup"));

        MvcResult qrResult = mockMvc.perform(get("/2fa/qr").cookie(passwordSession))
            .andExpect(status().isOk())
            .andExpect(header().string("Content-Type", "image/png"))
            .andReturn();
        assertThat(qrResult.getResponse().getContentAsByteArray()).isNotEmpty();
    }

    @Test
    void publicRegistrationValidatesInputAndNeverAcceptsSubmittedRoles() throws Exception {
        mockMvc.perform(post("/cadastro").with(csrf()))
            .andExpect(status().isOk())
            .andExpect(model().attributeHasFieldErrors(
                "registrationForm",
                "fullName",
                "username",
                "email",
                "password",
                "confirmPassword"
            ));

        mockMvc.perform(post("/cadastro").with(csrf())
                .param("fullName", "Usuario de Teste")
                .param("username", REGISTERED)
                .param("email", "email-invalido")
                .param("password", PASSWORD)
                .param("confirmPassword", PASSWORD))
            .andExpect(status().isOk())
            .andExpect(model().attributeHasFieldErrors("registrationForm", "email"));

        mockMvc.perform(post("/cadastro").with(csrf())
                .param("fullName", "Usuario de Teste")
                .param("username", REGISTERED)
                .param("email", REGISTERED + "@example.com")
                .param("password", PASSWORD)
                .param("confirmPassword", PASSWORD)
                .param("roles", "ROLE_ADMIN"))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/cadastro/pendente"));

        UserAccount registered = userRepository.findByUsername(REGISTERED).orElseThrow();
        assertThat(registered.getFullName()).isEqualTo("Usuario de Teste");
        assertThat(registered.getRoles()).containsExactly(Role.ROLE_USER);
        assertThat(registered.isEnabled()).isFalse();
        assertThat(registered.getPasswordHash()).startsWith("$2").doesNotContain(PASSWORD);
    }

    @Test
    void duplicateRegistrationIsRejected() throws Exception {
        createAccount(REGISTERED, Role.ROLE_USER);

        mockMvc.perform(post("/cadastro").with(csrf())
                .param("fullName", "Usuario de Teste")
                .param("username", REGISTERED)
                .param("email", "outro-security-test@example.com")
                .param("password", PASSWORD)
                .param("confirmPassword", PASSWORD))
            .andExpect(status().isOk())
            .andExpect(view().name("auth/register"))
            .andExpect(model().attributeHasErrors("registrationForm"));
    }

    @Test
    void threeInvalidPasswordsLockTheAccountAndUnknownUserStaysGeneric() throws Exception {
        createAccount(USERNAME, Role.ROLE_USER);

        for (int attempt = 0; attempt < 3; attempt++) {
            mockMvc.perform(formLogin("/login").user(USERNAME).password("Senha-Incorreta-2026!"))
                .andExpect(unauthenticated())
                .andExpect(redirectedUrl("/login?error"));
        }

        UserAccount locked = userRepository.findByUsername(USERNAME).orElseThrow();
        assertThat(locked.isCurrentlyLocked()).isTrue();
        mockMvc.perform(formLogin("/login").user(USERNAME).password(PASSWORD))
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error"));
        mockMvc.perform(formLogin("/login").user("usuario-inexistente").password(PASSWORD))
            .andExpect(unauthenticated())
            .andExpect(redirectedUrl("/login?error"));
    }

    @Test
    void csrfRejectsStateChangingRequestWithoutToken() throws Exception {
        mockMvc.perform(post("/senha/esqueci").param("email", "cliente@exemplo.com"))
            .andExpect(status().isForbidden());
    }

    @Test
    void invalidEmailIsRejectedByBackendValidation() throws Exception {
        mockMvc.perform(post("/senha/esqueci").with(csrf()).param("email", "email-invalido"))
            .andExpect(status().isOk())
            .andExpect(view().name("auth/forgot-password"))
            .andExpect(model().attributeHasFieldErrors("emailRequestForm", "email"));
    }

    @Test
    void logoutRequiresPostAndCsrf() throws Exception {
        Cookie sessionCookie = login(createAccount(USERNAME, Role.ROLE_USER));

        mockMvc.perform(get("/logout").cookie(sessionCookie))
            .andExpect(status().isNotFound());
        mockMvc.perform(post("/logout").cookie(sessionCookie))
            .andExpect(status().isForbidden());
        mockMvc.perform(post("/logout").with(csrf()).cookie(sessionCookie))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login?logout"));
        mockMvc.perform(get("/usuario").cookie(sessionCookie))
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl("/login"));
    }

    private String createAccount(String username, Role role) {
        UserAccount account = new UserAccount();
        account.setUsername(username);
        account.setEmail(username + "@example.com");
        account.setPasswordHash(passwordEncoder.encode(PASSWORD));
        account.setRoles(EnumSet.of(role));
        account.setEnabled(true);
        account.setTwoFactorEnabled(true);
        account.setTotpSecret(TOTP_SECRET);
        account.setEmailVerifiedAt(Instant.now());
        account.setCreatedAt(Instant.now());
        account.setUpdatedAt(Instant.now());
        userRepository.save(account);
        return username;
    }

    private Cookie login(String username) throws Exception {
        MvcResult passwordResult = mockMvc.perform(formLogin("/login").user(username).password(PASSWORD))
            .andExpect(authenticated().withUsername(username))
            .andExpect(redirectedUrl("/2fa/verificar"))
            .andReturn();
        Cookie passwordSession = passwordResult.getResponse().getCookie("SESSION");

        MvcResult twoFactorResult = mockMvc.perform(post("/2fa/verificar")
                .with(csrf())
                .cookie(passwordSession)
                .param("code", totpService.currentCode(TOTP_SECRET)))
            .andExpect(redirectedUrl("/dashboard"))
            .andReturn();
        Cookie renewedSession = twoFactorResult.getResponse().getCookie("SESSION");
        return renewedSession != null ? renewedSession : passwordSession;
    }

    private void removeTestAccount(String username) {
        userSessionService.invalidateAll(username);
        userRepository.findByUsername(username).ifPresent(account -> {
            verificationTokenRepository.deleteByUserId(account.getId());
            passwordResetTokenRepository.deleteByUserId(account.getId());
            userRepository.delete(account);
        });
    }
}
