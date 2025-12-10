package restoauth.authorization.config;


import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("prod")
public class ProdAuthorizationServerConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        return null;
    }
}
