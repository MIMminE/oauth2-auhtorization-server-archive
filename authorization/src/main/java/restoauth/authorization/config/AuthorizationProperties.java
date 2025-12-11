package restoauth.authorization.config;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "authorization")
@Component
@Getter
public class AuthorizationProperties {

    private final Token token = new Token();
    private final List<Client> clients = new ArrayList<>();
    private final Url url = new Url();

    @Data
    public static class Token {
        private long accessValidSeconds;
        private long refreshValidSeconds;
        private boolean useRefreshToken;
    }

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String[] scopes;
        private String grantTypes;
        private final Jwk jwk = new Jwk();
    }

    @Data
    public static class Url {
        private String token;
        private String key;
    }

    @Data
    public static class Jwk {
        private String jksPath;
        private String jksPassword;
        private String jksAlias;
    }
}