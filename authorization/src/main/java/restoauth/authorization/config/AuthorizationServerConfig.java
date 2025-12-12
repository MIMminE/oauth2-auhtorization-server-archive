package restoauth.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import restoauth.authorization.key.JWKProvider;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final AuthorizationProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationProvider authenticationProvider) throws Exception {
        AuthorizationProperties.Url urlProperties = properties.getUrl();

        http
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2AuthorizationServer(oauth -> oauth
                        .tokenEndpoint(token -> token
                                .authenticationProviders(provider -> {
                                    provider.add(0, authenticationProvider);
                                })
//                                .accessTokenResponseHandler(new TokenResponseHandler())
                        )
                        .authorizationServerSettings(AuthorizationServerSettings.builder()
                                .authorizationEndpoint(urlProperties.getToken())
                                .jwkSetEndpoint(urlProperties.getKey())
                                .build())
                        .oidc(Customizer.withDefaults())
                )
        ;
        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<AuthorizationProperties.Client> clientsProperties = properties.getClients();

        List<RegisteredClient> clientList = clientsProperties.stream().map(clientProperties -> {
            RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientProperties.getClientId())
                    .clientSecret(clientProperties.getClientSecret())
                    .authorizationGrantType(new AuthorizationGrantType(clientProperties.getGrantTypes()));

            Arrays.stream(clientProperties.getScopes()).forEach(clientBuilder::scope);
            return clientBuilder.build();
        }).toList();
        return new InMemoryRegisteredClientRepository(clientList);
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            String clientId = context.getRegisteredClient().getClientId();
            context.getJwsHeader().keyId(clientId);
        };
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(List<JWKProvider> jwkProviders) {
        JWKSet jwkSet = new JWKSet(jwkProviders.stream()
                .map(JWKProvider::getKeyPair)
                .toList());

        return new ImmutableJWKSet<>(jwkSet);
    }
}