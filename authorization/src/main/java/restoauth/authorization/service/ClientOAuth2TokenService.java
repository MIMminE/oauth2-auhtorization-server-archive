package restoauth.authorization.service;

import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;

import java.util.Optional;

public interface ClientOAuth2TokenService {
    Optional<OAuth2Authorization> getAuthorizationByClientId(String clientId);

    void saveAuthorization(String clientID, OAuth2Authorization authorization);

    void removeAuthorization(String clientID);
}
