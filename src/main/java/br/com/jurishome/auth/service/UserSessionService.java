package br.com.jurishome.auth.service;

import org.mongodb.spring.session.MongoIndexedSessionRepository;
import org.springframework.stereotype.Service;

@Service
public class UserSessionService {

    private final MongoIndexedSessionRepository sessionRepository;

    public UserSessionService(MongoIndexedSessionRepository sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    public void invalidateAll(String username) {
        sessionRepository.findByPrincipalName(username)
            .keySet()
            .forEach(sessionRepository::deleteById);
    }
}
