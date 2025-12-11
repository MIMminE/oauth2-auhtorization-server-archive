package restoauth.authorization.key;

import com.nimbusds.jose.jwk.JWK;

public interface JWKProvider {
    JWK getKeyPair();
}