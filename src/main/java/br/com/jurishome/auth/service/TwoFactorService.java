package br.com.jurishome.auth.service;

import java.time.Instant;

import org.springframework.stereotype.Service;

import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.exception.BusinessException;
import br.com.jurishome.auth.repository.UserAccountRepository;

@Service
public class TwoFactorService {

    private final UserAccountRepository repository;
    private final TotpService totpService;
    private final UserSessionService userSessionService;

    public TwoFactorService(
        UserAccountRepository repository,
        TotpService totpService,
        UserSessionService userSessionService
    ) {
        this.repository = repository;
        this.totpService = totpService;
        this.userSessionService = userSessionService;
    }

    public boolean isEnabled(String username) {
        UserAccount account = findByUsername(username);
        return account.isTwoFactorEnabled() && hasSecret(account);
    }

    public String prepareEnrollment(String username) {
        UserAccount account = findByUsername(username);
        if (account.isTwoFactorEnabled() && hasSecret(account)) {
            throw new BusinessException("O autenticador ja esta configurado.");
        }
        if (!hasSecret(account)) {
            account.setTotpSecret(totpService.generateSecret());
            account.setUpdatedAt(Instant.now());
            repository.save(account);
        }
        return account.getTotpSecret();
    }

    public String provisioningUri(String username) {
        String secret = prepareEnrollment(username);
        return totpService.provisioningUri(username, secret);
    }

    public byte[] qrCode(String username) {
        return totpService.createQrCode(provisioningUri(username));
    }

    public boolean activate(String username, String code) {
        UserAccount account = findByUsername(username);
        if (!hasSecret(account) || !totpService.verify(account.getTotpSecret(), normalizeCode(code))) {
            return false;
        }
        account.setTwoFactorEnabled(true);
        account.setUpdatedAt(Instant.now());
        repository.save(account);
        return true;
    }

    public boolean verify(String username, String code) {
        UserAccount account = findByUsername(username);
        return account.isTwoFactorEnabled()
            && hasSecret(account)
            && totpService.verify(account.getTotpSecret(), normalizeCode(code));
    }

    public void reset(String userId) {
        UserAccount account = repository.findById(userId)
            .orElseThrow(() -> new BusinessException("Usuario nao encontrado."));
        account.setTwoFactorEnabled(false);
        account.setTotpSecret(null);
        account.setUpdatedAt(Instant.now());
        repository.save(account);
        userSessionService.invalidateAll(account.getUsername());
    }

    private UserAccount findByUsername(String username) {
        return repository.findByUsername(username)
            .orElseThrow(() -> new BusinessException("Usuario nao encontrado."));
    }

    private boolean hasSecret(UserAccount account) {
        return account.getTotpSecret() != null && !account.getTotpSecret().isBlank();
    }

    private String normalizeCode(String code) {
        return code == null ? "" : code.replaceAll("\\s", "");
    }
}
