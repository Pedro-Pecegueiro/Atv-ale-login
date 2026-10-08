package br.com.jurishome.auth.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.data.mongodb.core.MongoOperations;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import br.com.jurishome.auth.config.RegistrationVerificationProperties;
import br.com.jurishome.auth.domain.EmailVerificationToken;
import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.EmailVerificationTokenRepository;

@Service
public class RegistrationVerificationService {

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserAccountService userService;
    private final MongoOperations mongoOperations;
    private final JavaMailSender mailSender;
    private final RegistrationVerificationProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public RegistrationVerificationService(
        EmailVerificationTokenRepository tokenRepository,
        UserAccountService userService,
        MongoOperations mongoOperations,
        JavaMailSender mailSender,
        RegistrationVerificationProperties properties
    ) {
        this.tokenRepository = tokenRepository;
        this.userService = userService;
        this.mongoOperations = mongoOperations;
        this.mailSender = mailSender;
        this.properties = properties;
    }

    public Delivery issue(UserAccount account) {
        tokenRepository.deleteByUserId(account.getId());

        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        Instant now = Instant.now();

        EmailVerificationToken verificationToken = new EmailVerificationToken();
        verificationToken.setTokenHash(hash(rawToken));
        verificationToken.setUserId(account.getId());
        verificationToken.setCreatedAt(now);
        verificationToken.setExpiresAt(now.plus(properties.tokenDuration()));
        tokenRepository.save(verificationToken);

        String verificationUrl = UriComponentsBuilder.fromUriString(properties.baseUrl())
            .path("/cadastro/confirmar")
            .queryParam("token", rawToken)
            .build()
            .encode()
            .toUriString();

        if (properties.delivery() == RegistrationVerificationProperties.Delivery.SMTP) {
            sendEmail(account.getEmail(), verificationUrl);
            return new Delivery(null);
        }
        return new Delivery(verificationUrl);
    }

    public Delivery resend(String email) {
        Optional<UserAccount> account = userService.findPendingByEmail(email);
        return account.map(this::issue).orElseGet(() -> new Delivery(null));
    }

    public void confirm(String rawToken) {
        if (rawToken == null || rawToken.isBlank() || rawToken.length() > 200) {
            throw new BusinessException("Link de confirmacao invalido.");
        }
        Query query = Query.query(
            Criteria.where("tokenHash").is(hash(rawToken))
                .and("expiresAt").gt(Instant.now())
        );
        EmailVerificationToken verificationToken = mongoOperations.findAndRemove(
            query,
            EmailVerificationToken.class
        );
        if (verificationToken == null) {
            throw new BusinessException("Link de confirmacao invalido, expirado ou ja utilizado.");
        }
        userService.confirmRegistration(verificationToken.getUserId());
    }

    private void sendEmail(String recipient, String verificationUrl) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.from());
        message.setTo(recipient);
        message.setSubject("Confirme seu cadastro no JurisHome");
        message.setText("Confirme seu cadastro acessando o link: " + verificationUrl);
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

    public record Delivery(String localVerificationUrl) {
    }
}
