package br.com.jurishome.auth.service;

import java.util.Locale;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import br.com.jurishome.auth.domain.UserAccount;
import br.com.jurishome.auth.repository.UserAccountRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserAccountRepository repository;

    public CustomUserDetailsService(UserAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    public UserDetails loadUserByUsername(String login) throws UsernameNotFoundException {
        String normalized = login.trim().toLowerCase(Locale.ROOT);
        UserAccount account = repository.findByUsernameOrEmail(normalized, normalized)
            .orElseThrow(() -> new UsernameNotFoundException("Credenciais invalidas."));

        String[] authorities = account.getRoles().stream()
            .map(Enum::name)
            .toArray(String[]::new);

        return User.withUsername(account.getUsername())
            .password(account.getPasswordHash())
            .authorities(authorities)
            .disabled(!account.isEnabled())
            .accountLocked(account.isCurrentlyLocked())
            .build();
    }
}
