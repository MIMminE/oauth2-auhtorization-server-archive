package restoauth.authorization.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import restoauth.authorization.key.DevRsaKeyPairProvider;
import restoauth.authorization.key.JWKProvider;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
@Profile("dev")
public class DevKeyProviderConfig {

    private final AuthorizationProperties properties;

    @Bean
    public List<JWKProvider> jwkProviders() {
        List<JWKProvider> jwkProviders = new ArrayList<>();
        properties.getClients().forEach(client -> jwkProviders.add(new DevRsaKeyPairProvider(client.getClientId())));
        return jwkProviders;
    }
}