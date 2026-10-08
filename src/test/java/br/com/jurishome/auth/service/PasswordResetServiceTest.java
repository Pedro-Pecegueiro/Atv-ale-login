package br.com.jurishome.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.mail.javamail.JavaMailSender;

import br.com.jurishome.auth.config.PasswordResetProperties;
import br.com.jurishome.auth.domain.PasswordResetToken;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.PasswordResetTokenRepository;

@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private PasswordResetTokenRepository tokenRepository;
    @Mock
    private UserAccountService userService;
    @Mock
    private UserSessionService userSessionService;
    @Mock
    private MongoOperations mongoOperations;
    @Mock
    private JavaMailSender mailSender;
    private PasswordResetService service;

    @BeforeEach
    void setUp() {
        service = new PasswordResetService(
            tokenRepository,
            userService,
            userSessionService,
            mongoOperations,
            mailSender,
            new PasswordResetProperties(
                PasswordResetProperties.Delivery.SCREEN,
                "http://localhost:8080",
                Duration.ofMinutes(30),
                "noreply@jurishome.local"
            )
        );
    }

    @Test
    void requestStoresOnlyTokenHash() {
        UserAccount account = account();
        when(userService.findEnabledByEmail(account.getEmail())).thenReturn(Optional.of(account));
        when(tokenRepository.save(any(PasswordResetToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PasswordResetService.Delivery delivery = service.request(account.getEmail());

        ArgumentCaptor<PasswordResetToken> captor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(tokenRepository).save(captor.capture());
        PasswordResetToken saved = captor.getValue();
        assertThat(saved.getTokenHash()).hasSize(64);
        assertThat(delivery.localResetUrl()).startsWith("http://localhost:8080/senha/redefinir?token=");
        assertThat(delivery.localResetUrl()).doesNotContain(saved.getTokenHash());
        verify(tokenRepository).deleteByUserId(account.getId());
    }

    @Test
    void resetChangesPasswordAndInvalidatesSessions() throws Exception {
        String rawToken = "token-seguro-de-teste";
        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setUserId("user-id");
        resetToken.setExpiresAt(Instant.now().plusSeconds(300));
        UserAccount account = account();
        when(mongoOperations.findAndRemove(any(), org.mockito.ArgumentMatchers.eq(PasswordResetToken.class)))
            .thenReturn(resetToken);
        when(userService.resetPassword("user-id", "Nova-Senha-2026!")).thenReturn(account);

        service.reset(rawToken, "Nova-Senha-2026!", "Nova-Senha-2026!");

        verify(userService).resetPassword("user-id", "Nova-Senha-2026!");
        verify(userSessionService).invalidateAll(account.getUsername());
    }

    @Test
    void resetRejectsDifferentPasswords() {
        assertThatThrownBy(() -> service.reset("token", "Nova-Senha-2026!", "Outra-Senha-2026!"))
            .isInstanceOf(BusinessException.class)
            .hasMessageContaining("nao coincidem");
    }

    private UserAccount account() {
        UserAccount account = new UserAccount();
        account.setId("user-id");
        account.setUsername("cliente.jurishome");
        account.setEmail("cliente@jurishome.local");
        account.setEnabled(true);
        return account;
    }

}
