package restoauth.authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import restoauth.authorization.key.KeyPairProvider;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.UUID;


@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final KeyPairProvider keyPairProvider;
    private final AuthorizationProperties properties;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        AuthorizationProperties.Url urlProperties = properties.getUrl();

        http
                .authorizeHttpRequests(authorize
                        -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2AuthorizationServer(oauth -> oauth
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
        AuthorizationProperties.Client clientProperties = properties.getClient();

        RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientProperties.getClientId())
                .clientSecret(clientProperties.getClientSecret())
                .scope("message.read")
                .scope("message.write")
                .authorizationGrantType(new AuthorizationGrantType(clientProperties.getGrantTypes()));

        Arrays.stream(clientProperties.getScopes()).forEach(clientBuilder::scope);

        RegisteredClient client = clientBuilder.build();
        return new InMemoryRegisteredClientRepository(client);
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = keyPairProvider.getKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyPairProvider.getKeyId())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }
}