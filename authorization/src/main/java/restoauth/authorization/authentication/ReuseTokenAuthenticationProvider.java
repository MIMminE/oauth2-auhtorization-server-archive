package restoauth.authorization.authentication;

import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import restoauth.authorization.service.ClientOAuth2TokenService;

import java.time.Instant;
import java.util.Objects;

@Component
@RequiredArgsConstructor
public class ReuseTokenAuthenticationProvider implements AuthenticationProvider {

    private final ClientOAuth2TokenService clientOAuth2TokenService;

    @Override
    public @Nullable Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientCredentialsAuthenticationToken token = (OAuth2ClientCredentialsAuthenticationToken) authentication;
        OAuth2ClientAuthenticationToken credentials = (OAuth2ClientAuthenticationToken) token.getPrincipal();
        RegisteredClient registeredClient = Objects.requireNonNull(credentials).getRegisteredClient();
        String clientId = Objects.requireNonNull(registeredClient).getClientId();

        OAuth2Authorization oAuth2Authorization = clientOAuth2TokenService.getAuthorizationByClientId(clientId).orElse(null);

        if (oAuth2Authorization == null) {
            return null;
        }

        boolean expired = oAuth2Authorization.getAccessToken().isExpired();
        if (expired) {
            return null;
        }

        OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                oAuth2Authorization.getAccessToken().getToken().getTokenValue(),
                Instant.now(),
                oAuth2Authorization.getAccessToken().getToken().getExpiresAt(),
                oAuth2Authorization.getAccessToken().getToken().getScopes()
        );


        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient,
                credentials,
                oAuth2AccessToken
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientCredentialsAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
