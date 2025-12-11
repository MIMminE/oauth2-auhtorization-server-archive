package restoauth.authorization.key;

import com.nimbusds.jose.jwk.JWK;
import org.springframework.stereotype.Component;

public class ProdKeyPairProvider implements JWKProvider{

    @Override
    public JWK getKeyPair() {
        return null;
    }
}
