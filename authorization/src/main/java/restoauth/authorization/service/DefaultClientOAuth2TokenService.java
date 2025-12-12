package restoauth.authorization.service;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DefaultClientOAuth2TokenService implements ClientOAuth2TokenService {

    private final Map<String, OAuth2Authorization> authorizationStore = new ConcurrentHashMap<>();

    @Override
    public Optional<OAuth2Authorization> getAuthorizationByClientId(String clientId) {
        if (authorizationStore.containsKey(clientId)) {
            return Optional.ofNullable(authorizationStore.get(clientId));
        }
        return Optional.empty();
    }

    @Override
    public void saveAuthorization(String clientID, OAuth2Authorization authorization) {
        authorizationStore.put(clientID, authorization);
    }

    @Override
    public void removeAuthorization(String clientID) {
        authorizationStore.remove(clientID);
    }
}