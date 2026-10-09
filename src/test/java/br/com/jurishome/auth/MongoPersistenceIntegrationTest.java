package br.com.jurishome.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.EnumSet;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mongodb.spring.session.MongoIndexedSessionRepository;
import org.mongodb.spring.session.MongoSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.dao.DuplicateKeyException;

import br.com.jurishome.auth.domain.Role;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.repository.UserAccountRepository;

@SpringBootTest
class MongoPersistenceIntegrationTest {

    @Autowired
    private UserAccountRepository userRepository;
    @Autowired
    private MongoIndexedSessionRepository sessionRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private String createdUserId;
    private String createdSessionId;

    @AfterEach
    void cleanUp() {
        if (createdSessionId != null) {
            sessionRepository.deleteById(createdSessionId);
        }
        if (createdUserId != null) {
            userRepository.deleteById(createdUserId);
        }
    }

    @Test
    void userAndPasswordHashArePersistedInMongoDb() {
        String suffix = UUID.randomUUID().toString();
        UserAccount account = new UserAccount();
        account.setFullName("Usuario de Integracao");
        account.setUsername("teste-" + suffix);
        account.setEmail("teste-" + suffix + "@example.com");
        account.setPasswordHash(passwordEncoder.encode("Senha-Forte-2026!"));
        account.setRoles(EnumSet.of(Role.ROLE_USER));
        account.setEnabled(true);
        account.setCreatedAt(Instant.now());
        account.setUpdatedAt(Instant.now());

        UserAccount saved = userRepository.save(account);
        createdUserId = saved.getId();

        UserAccount loaded = userRepository.findById(saved.getId()).orElseThrow();
        assertThat(loaded.getFullName()).isEqualTo("Usuario de Integracao");
        assertThat(loaded.getPasswordHash()).startsWith("$2").doesNotContain("Senha-Forte-2026!");
        assertThat(loaded.getRoles()).containsExactly(Role.ROLE_USER);
    }

    @Test
    void httpSessionIsPersistedAndCanBeInvalidated() {
        MongoSession session = sessionRepository.createSession();
        session.setAttribute(
            FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME,
            "integration-test-user"
        );
        sessionRepository.save(session);
        createdSessionId = session.getId();

        assertThat(sessionRepository.findById(session.getId())).isNotNull();
        assertThat(sessionRepository.findByPrincipalName("integration-test-user"))
            .containsKey(session.getId());

        sessionRepository.deleteById(session.getId());
        createdSessionId = null;
        assertThat(sessionRepository.findById(session.getId())).isNull();
    }

    @Test
    void configuredSessionTimeoutIsApplied() {
        assertThat(sessionRepository.createSession().getMaxInactiveInterval())
            .isEqualTo(java.time.Duration.ofMinutes(30));
    }

    @Test
    void uniqueEmailIndexRejectsDuplicateAccounts() {
        String suffix = UUID.randomUUID().toString();
        UserAccount first = account("first-" + suffix, "unique-" + suffix + "@example.com");
        UserAccount saved = userRepository.save(first);
        createdUserId = saved.getId();

        UserAccount duplicate = account("second-" + suffix, first.getEmail());
        assertThatThrownBy(() -> userRepository.save(duplicate))
            .isInstanceOf(DuplicateKeyException.class);
    }

    private UserAccount account(String username, String email) {
        UserAccount account = new UserAccount();
        account.setUsername(username);
        account.setEmail(email);
        account.setPasswordHash(passwordEncoder.encode("Senha-Forte-2026!"));
        account.setRoles(EnumSet.of(Role.ROLE_USER));
        account.setEnabled(true);
        account.setCreatedAt(Instant.now());
        account.setUpdatedAt(Instant.now());
        return account;
    }
}
