package restoauth.authorization.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class ClientOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final InMemoryOAuth2AuthorizationService inMemoryOAuth2AuthorizationService = new InMemoryOAuth2AuthorizationService();
    private final ClientOAuth2TokenService clientOAuth2TokenService;

    @Override
    public void save(OAuth2Authorization authorization) {
        String registeredClientId = authorization.getPrincipalName();
        clientOAuth2TokenService.saveAuthorization(registeredClientId, authorization);
        inMemoryOAuth2AuthorizationService.save(authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        String registeredClientId = authorization.getPrincipalName();
        clientOAuth2TokenService.removeAuthorization(registeredClientId);
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