package br.com.jurishome.auth.service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import br.com.jurishome.auth.config.AppSecurityProperties;
import br.com.jurishome.auth.domain.Role;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.dto.AdminUserUpdateForm;
import br.com.jurishome.auth.dto.RegistrationForm;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.UserAccountRepository;

@Service
public class UserAccountService {

    private final UserAccountRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final AppSecurityProperties securityProperties;
    private final UserSessionService userSessionService;

    public UserAccountService(
        UserAccountRepository repository,
        PasswordEncoder passwordEncoder,
        AppSecurityProperties securityProperties,
        UserSessionService userSessionService
    ) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.securityProperties = securityProperties;
        this.userSessionService = userSessionService;
    }

    public UserAccount register(RegistrationForm form) {
        if (!form.getPassword().equals(form.getConfirmPassword())) {
            throw new BusinessException("As senhas nao coincidem.");
        }
        validatePassword(form.getPassword());

        String username = normalize(form.getUsername());
        String email = normalize(form.getEmail());
        ensureAvailable(username, email);

        UserAccount account = new UserAccount();
        account.setFullName(normalizeFullName(form.getFullName()));
        account.setUsername(username);
        account.setEmail(email);
        account.setPasswordHash(passwordEncoder.encode(form.getPassword()));
        account.setRoles(EnumSet.of(Role.ROLE_USER));
        account.setEnabled(false);
        account.setCreatedAt(Instant.now());
        account.setUpdatedAt(Instant.now());

        try {
            return repository.save(account);
        } catch (DuplicateKeyException ex) {
            throw new BusinessException("Nome de usuario ou e-mail ja cadastrado.");
        }
    }

    public UserAccount createBootstrapAdmin(String usernameValue, String emailValue, String rawPassword) {
        String username = normalize(usernameValue);
        String email = normalize(emailValue);
        if (repository.existsByUsername(username) || repository.existsByEmail(email)) {
            return repository.findByUsername(username).orElseGet(() -> repository.findByEmail(email).orElseThrow());
        }
        validatePassword(rawPassword);

        UserAccount account = new UserAccount();
        account.setUsername(username);
        account.setEmail(email);
        account.setPasswordHash(passwordEncoder.encode(rawPassword));
        account.setRoles(EnumSet.allOf(Role.class));
        account.setEnabled(true);
        account.setEmailVerifiedAt(Instant.now());
        account.setCreatedAt(Instant.now());
        account.setUpdatedAt(Instant.now());
        return repository.save(account);
    }

    public List<UserAccount> findAll() {
        return repository.findAll(Sort.by(Sort.Direction.ASC, "username"));
    }

    public UserAccount findById(String id) {
        return repository.findById(id)
            .orElseThrow(() -> new BusinessException("Usuario nao encontrado."));
    }

    public UserAccount findByLogin(String login) {
        String normalized = normalize(login);
        return repository.findByUsernameOrEmail(normalized, normalized)
            .orElseThrow(() -> new BusinessException("Usuario nao encontrado."));
    }

    public Optional<UserAccount> findPendingByEmail(String emailValue) {
        String email = normalize(emailValue);
        return repository.findByEmail(email)
            .filter(account -> !account.isEnabled() && account.getEmailVerifiedAt() == null);
    }

    public Optional<UserAccount> findEnabledByEmail(String emailValue) {
        String email = normalize(emailValue);
        return repository.findByEmail(email).filter(UserAccount::isEnabled);
    }

    public void confirmRegistration(String userId) {
        UserAccount account = findById(userId);
        if (account.getEmailVerifiedAt() == null) {
            Instant now = Instant.now();
            account.setEmailVerifiedAt(now);
            account.setEnabled(true);
            account.setUpdatedAt(now);
            repository.save(account);
        }
    }

    public UserAccount resetPassword(String userId, String rawPassword) {
        validatePassword(rawPassword);
        UserAccount account = findById(userId);
        account.setPasswordHash(passwordEncoder.encode(rawPassword));
        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        account.setUpdatedAt(Instant.now());
        return repository.save(account);
    }

    public void updateByAdmin(String id, AdminUserUpdateForm form, String currentUsername) {
        UserAccount account = findById(id);
        if (account.getUsername().equals(normalize(currentUsername))
            && (!form.isEnabled() || !form.getRoles().contains(Role.ROLE_ADMIN))) {
            throw new BusinessException("Voce nao pode desativar sua propria conta nem remover seu perfil de administrador.");
        }
        protectLastAdministrator(account, form.getRoles(), form.isEnabled());
        boolean accessChanged = account.isEnabled() != form.isEnabled()
            || !account.getRoles().equals(form.getRoles());
        account.setRoles(Set.copyOf(form.getRoles()));
        account.setEnabled(form.isEnabled());
        account.setUpdatedAt(Instant.now());
        repository.save(account);
        if (accessChanged) {
            userSessionService.invalidateAll(account.getUsername());
        }
    }

    public void unlock(String id) {
        UserAccount account = findById(id);
        account.setFailedLoginAttempts(0);
        account.setLockedUntil(null);
        account.setUpdatedAt(Instant.now());
        repository.save(account);
    }

    public void deleteByAdmin(String id, String currentUsername) {
        UserAccount account = findById(id);
        if (account.getUsername().equals(normalize(currentUsername))) {
            throw new BusinessException("Voce nao pode excluir a propria conta.");
        }
        protectLastAdministrator(account, Set.of(), false);
        userSessionService.invalidateAll(account.getUsername());
        repository.delete(account);
    }

    public void recordLoginFailure(String submittedLogin) {
        String normalized = normalize(submittedLogin);
        repository.findByUsernameOrEmail(normalized, normalized).ifPresent(account -> {
            if (!account.isEnabled()) {
                return;
            }
            Instant now = Instant.now();
            if (account.getLockedUntil() != null && account.getLockedUntil().isAfter(now)) {
                return;
            }
            if (account.getLockedUntil() != null) {
                account.setLockedUntil(null);
                account.setFailedLoginAttempts(0);
            }
            int attempts = account.getFailedLoginAttempts() + 1;
            if (attempts >= securityProperties.maxFailedAttempts()) {
                account.setLockedUntil(now.plus(securityProperties.lockDuration()));
                attempts = 0;
            }
            account.setFailedLoginAttempts(attempts);
            account.setUpdatedAt(now);
            repository.save(account);
        });
    }

    public void recordLoginSuccess(String username) {
        repository.findByUsername(normalize(username)).ifPresent(account -> {
            account.setFailedLoginAttempts(0);
            account.setLockedUntil(null);
            account.setLastLoginAt(Instant.now());
            account.setUpdatedAt(Instant.now());
            repository.save(account);
        });
    }

    private void ensureAvailable(String username, String email) {
        if (repository.existsByUsername(username)) {
            throw new BusinessException("Nome de usuario ja cadastrado.");
        }
        if (repository.existsByEmail(email)) {
            throw new BusinessException("E-mail ja cadastrado.");
        }
    }

    private void protectLastAdministrator(UserAccount account, Set<Role> newRoles, boolean newEnabled) {
        boolean removesActiveAdmin = account.isEnabled()
            && account.getRoles().contains(Role.ROLE_ADMIN)
            && (!newEnabled || !newRoles.contains(Role.ROLE_ADMIN));
        if (removesActiveAdmin && repository.countByRolesContainingAndEnabledTrue(Role.ROLE_ADMIN) <= 1) {
            throw new BusinessException("O sistema precisa manter pelo menos um administrador ativo.");
        }
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeFullName(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", " ");
    }

    private boolean isStrongPassword(String value) {
        return value != null
            && value.length() >= 12
            && value.length() <= 72
            && value.getBytes(StandardCharsets.UTF_8).length <= 72
            && value.matches(".*[a-z].*")
            && value.matches(".*[A-Z].*")
            && value.matches(".*\\d.*")
            && value.matches(".*[^A-Za-z0-9].*");
    }

    private void validatePassword(String value) {
        if (!isStrongPassword(value)) {
            throw new BusinessException(
                "A senha deve ter entre 12 e 72 caracteres, ocupar no maximo 72 bytes e conter maiuscula, minuscula, numero e simbolo."
            );
        }
    }
}
