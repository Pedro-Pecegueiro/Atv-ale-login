package br.com.jurishome.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import br.com.jurishome.auth.config.PasswordResetProperties;
import br.com.jurishome.auth.domain.PasswordResetToken;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.PasswordResetTokenRepository;

@Service
public class PasswordResetService {

    private final PasswordResetTokenRepository tokenRepository;
    private final UserAccountService userService;
    private final UserSessionService userSessionService;
    private final MongoOperations mongoOperations;
    private final JavaMailSender mailSender;
    private final PasswordResetProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordResetService(
        PasswordResetTokenRepository tokenRepository,
        UserAccountService userService,
        UserSessionService userSessionService,
        MongoOperations mongoOperations,
        JavaMailSender mailSender,
        PasswordResetProperties properties
    ) {
        this.tokenRepository = tokenRepository;
        this.userService = userService;
        this.userSessionService = userSessionService;
        this.mongoOperations = mongoOperations;
        this.mailSender = mailSender;
        this.properties = properties;
    }

    public Delivery request(String email) {
        Optional<UserAccount> account = userService.findEnabledByEmail(email);
        return account.map(this::issue).orElseGet(() -> new Delivery(null));
    }

    public void validate(String rawToken) {
        findValidToken(rawToken);
    }

    public void reset(String rawToken, String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new BusinessException("As senhas nao coincidem.");
        }
        PasswordResetToken resetToken = consumeValidToken(rawToken);
        UserAccount account = userService.resetPassword(resetToken.getUserId(), password);
        userSessionService.invalidateAll(account.getUsername());
    }

    private Delivery issue(UserAccount account) {
        tokenRepository.deleteByUserId(account.getId());

        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Instant now = Instant.now();

        PasswordResetToken resetToken = new PasswordResetToken();
        resetToken.setTokenHash(hash(rawToken));
        resetToken.setUserId(account.getId());
        resetToken.setCreatedAt(now);
        resetToken.setExpiresAt(now.plus(properties.tokenDuration()));
        tokenRepository.save(resetToken);

        String resetUrl = UriComponentsBuilder.fromUriString(properties.baseUrl())
            .path("/senha/redefinir")
            .queryParam("token", rawToken)
            .build()
            .encode()
            .toUriString();

        if (properties.delivery() == PasswordResetProperties.Delivery.SMTP) {
            sendEmail(account.getEmail(), resetUrl);
            return new Delivery(null);
        }
        return new Delivery(resetUrl);
    }

    private PasswordResetToken findValidToken(String rawToken) {
        validateTokenFormat(rawToken);
        PasswordResetToken resetToken = tokenRepository.findByTokenHash(hash(rawToken))
            .orElseThrow(() -> new BusinessException("Link de recuperacao invalido ou ja utilizado."));
        if (!resetToken.getExpiresAt().isAfter(Instant.now())) {
            tokenRepository.delete(resetToken);
            throw new BusinessException("O link de recuperacao expirou. Solicite um novo link.");
        }
        return resetToken;
    }

    private PasswordResetToken consumeValidToken(String rawToken) {
        validateTokenFormat(rawToken);
        Query query = Query.query(
            Criteria.where("tokenHash").is(hash(rawToken))
                .and("expiresAt").gt(Instant.now())
        );
        PasswordResetToken resetToken = mongoOperations.findAndRemove(query, PasswordResetToken.class);
        if (resetToken == null) {
            throw new BusinessException("Link de recuperacao invalido, expirado ou ja utilizado.");
        }
        return resetToken;
    }

    private void validateTokenFormat(String rawToken) {
        if (rawToken == null || rawToken.isBlank() || rawToken.length() > 200) {
            throw new BusinessException("Link de recuperacao invalido.");
        }
    }

    private void sendEmail(String recipient, String resetUrl) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.from());
        message.setTo(recipient);
        message.setSubject("Recuperacao de senha do JurisHome");
        message.setText("Redefina sua senha acessando o link: " + resetUrl);
        mailSender.send(message);
    }

    private String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 nao esta disponivel.", ex);
        }
    }

    public record Delivery(String localResetUrl) {
    }
}
