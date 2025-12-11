package restoauth.authorization.key;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.KeyPair;

@Component
@Profile("prod")
public class ProdKeyPairProvider implements KeyPairProvider {

    @Override
    public KeyPair getKeyPair() {
        return null;
    }

    @Override
    public String getKeyId() {
        return "";
    }
}
