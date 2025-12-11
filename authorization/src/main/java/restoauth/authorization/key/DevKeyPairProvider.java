package restoauth.authorization.key;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
@Profile("dev")
public class DevKeyPairProvider implements KeyPairProvider {
    @Override
    public KeyPair getKeyPair() {
        return generateRsaKey();
    }

    @Override
    public String getKeyId() {
        return UUID.randomUUID().toString();
    }

    private KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}