package restoauth.authorization.key;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import lombok.RequiredArgsConstructor;

import java.util.UUID;

@RequiredArgsConstructor
public class DevRsaKeyPairProvider implements JWKProvider {

    private final String keyId;

    @Override
    public JWK getKeyPair() {
        try {
            return new RSAKeyGenerator(2048)
                    .keyID(keyId)
                    .generate();

        } catch (Exception ex) {
            throw new IllegalStateException("RSA 키 생성 실패", ex);
        }
    }
}