package restoauth.authorization.key;

import java.security.KeyPair;

public interface KeyPairProvider {
    KeyPair getKeyPair();
    String getKeyId();
}