package br.com.jurishome.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.EnumSet;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import br.com.jurishome.auth.config.AppSecurityProperties;
import br.com.jurishome.auth.domain.Role;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.dto.AdminUserUpdateForm;
import br.com.jurishome.auth.dto.RegistrationForm;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.UserAccountRepository;

@ExtendWith(MockitoExtension.class)
class UserAccountServiceTest {

    @Mock
    private UserAccountRepository repository;
    @Mock
    private UserSessionService userSessionService;
    private UserAccountService service;

    @BeforeEach
    void setUp() {
        service = new UserAccountService(
            repository,
            new BCryptPasswordEncoder(4),
            new AppSecurityProperties(3, Duration.ofMinutes(15)),
            userSessionService
        );
    }

    @Test
    void registrationNormalizesAndHashesCredentials() {
        RegistrationForm form = registrationForm();
        when(repository.save(any(UserAccount.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.register(form);

        ArgumentCaptor<UserAccount> captor = ArgumentCaptor.forClass(UserAccount.class);
        verify(repository).save(captor.capture());
        UserAccount saved = captor.getValue();
        assertThat(saved.getFullName()).isEqualTo("Maria da Silva");
        assertThat(saved.getUsername()).isEqualTo("cliente.jurishome");
        assertThat(saved.getEmail()).isEqualTo("aluna@exemplo.com");
        assertThat(saved.getPasswordHash()).isNotEqualTo(form.getPassword()).startsWith("$2");
        assertThat(saved.getRoles()).containsExactly(Role.ROLE_USER);
        assertThat(saved.isEnabled()).isFalse();
    }

    @Test
    void registrationRejectsMismatchedPasswords() {
        RegistrationForm form = registrationForm();
        form.setConfirmPassword("Outra-Senha-123!");

        assertThatThrownBy(() -> service.register(form))
            .isInstanceOf(BusinessException.class)
            .hasMessageContaining("nao coincidem");
    }

    @Test
    void thirdFailureLocksAccount() {
        UserAccount account = activeUser();
        when(repository.findByUsernameOrEmail("cliente.jurishome", "cliente.jurishome")).thenReturn(Optional.of(account));
        when(repository.save(any(UserAccount.class))).thenAnswer(invocation -> invocation.getArgument(0));

        for (int attempt = 0; attempt < 3; attempt++) {
            service.recordLoginFailure("Cliente.JurisHome");
        }

        assertThat(account.getLockedUntil()).isNotNull();
        assertThat(account.isCurrentlyLocked()).isTrue();
    }

    @Test
    void pendingRegistrationDoesNotAccumulatePasswordFailures() {
        UserAccount account = activeUser();
        account.setEnabled(false);
        when(repository.findByUsernameOrEmail("cliente.jurishome", "cliente.jurishome")).thenReturn(Optional.of(account));

        service.recordLoginFailure("Cliente.JurisHome");

        assertThat(account.getFailedLoginAttempts()).isZero();
        verify(repository, never()).save(any(UserAccount.class));
    }

    @Test
    void lastActiveAdministratorCannotBeDisabled() {
        UserAccount admin = activeUser();
        admin.setId("admin-id");
        admin.setUsername("root");
        admin.setRoles(EnumSet.of(Role.ROLE_ADMIN));
        when(repository.findById("admin-id")).thenReturn(Optional.of(admin));
        when(repository.countByRolesContainingAndEnabledTrue(Role.ROLE_ADMIN)).thenReturn(1L);
        AdminUserUpdateForm form = new AdminUserUpdateForm();
        form.setRoles(EnumSet.of(Role.ROLE_USER));
        form.setEnabled(true);

        assertThatThrownBy(() -> service.updateByAdmin("admin-id", form, "outro-admin"))
            .isInstanceOf(BusinessException.class)
            .hasMessageContaining("pelo menos um administrador");
    }

    @Test
    void changingRolesInvalidatesExistingSessions() {
        UserAccount account = activeUser();
        account.setId("user-id");
        when(repository.findById("user-id")).thenReturn(Optional.of(account));
        when(repository.save(any(UserAccount.class))).thenAnswer(invocation -> invocation.getArgument(0));
        AdminUserUpdateForm form = new AdminUserUpdateForm();
        form.setRoles(EnumSet.of(Role.ROLE_MODERATOR));
        form.setEnabled(true);

        service.updateByAdmin("user-id", form, "admin");

        verify(userSessionService).invalidateAll("cliente.jurishome");
    }

    private RegistrationForm registrationForm() {
        RegistrationForm form = new RegistrationForm();
        form.setFullName("  Maria   da Silva  ");
        form.setUsername(" Cliente.JurisHome ");
        form.setEmail(" Aluna@Exemplo.com ");
        form.setPassword("Senha-Forte-123!");
        form.setConfirmPassword("Senha-Forte-123!");
        return form;
    }

    private UserAccount activeUser() {
        UserAccount account = new UserAccount();
        account.setUsername("cliente.jurishome");
        account.setEmail("aluna@exemplo.com");
        account.setEnabled(true);
        account.setRoles(EnumSet.of(Role.ROLE_USER));
        return account;
    }
}
