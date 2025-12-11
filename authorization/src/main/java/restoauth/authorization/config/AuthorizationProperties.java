package restoauth.authorization.config;

import lombok.Data;
import lombok.Getter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "authorization")
@Component
@Getter
public class AuthorizationProperties {

    private final Token token = new Token();
    private final Jks jks = new Jks();
    private final Client client = new Client();
    private final Url url = new Url();

    @Data
    public static class Token {
        private long accessValidSeconds;
        private long refreshValidSeconds;
        private boolean useRefreshToken;
    }

    @Data
    public static class Jks {
        private String path;
        private String password;
        private String alias;
    }

    @Data
    public static class Client {
        private String clientId;
        private String clientSecret;
        private String redirectUri;
        private String[] scopes;
        private String grantTypes;
    }

    @Data
    public static class Url{
        private String token;
        private String key;
    }
}