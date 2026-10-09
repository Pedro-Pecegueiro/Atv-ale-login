package br.com.jurishome.auth.config;

import java.time.Duration;

import org.mongodb.spring.session.MongoIndexedSessionRepository;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.annotation.Value;
import org.mongodb.spring.session.config.annotation.web.http.EnableMongoHttpSession;
import org.springframework.session.config.SessionRepositoryCustomizer;

@Configuration
@EnableMongoHttpSession(collectionName = "sessions")
public class MongoSessionConfig {

    @Bean
    SessionRepositoryCustomizer<MongoIndexedSessionRepository> mongoSessionCustomizer(
        @Value("${spring.session.timeout:30m}") Duration sessionTimeout
    ) {
        // O mesmo prazo e aplicado a todas as sessoes gravadas na colecao sessions.
        return repository -> repository.setDefaultMaxInactiveInterval(sessionTimeout);
    }
}
