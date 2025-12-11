package restoauth.authorization.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@Component
public class CustomInmemoryService implements OAuth2AuthorizationService {

    private final InMemoryOAuth2AuthorizationService inMemoryOAuth2AuthorizationService = new InMemoryOAuth2AuthorizationService();
    public static final Map<String, OAuth2Authorization> store = new HashMap<>();

    @Override
    public void save(OAuth2Authorization authorization) {
        String registeredClientId = authorization.getRegisteredClientId();
        store.put(registeredClientId, authorization);
        inMemoryOAuth2AuthorizationService.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        inMemoryOAuth2AuthorizationService.remove(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        return inMemoryOAuth2AuthorizationService.findById(id);
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        return inMemoryOAuth2AuthorizationService.findByToken(token, tokenType);
    }
}