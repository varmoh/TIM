package ee.eesti.authentication.configuration;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Data
@ConfigurationProperties(prefix = "security")
@Configuration
public class SecurityProperties {
    private Oauth2Properties oauth2;
    private AllowlistProperties allowlist;

    @Data
    public class Oauth2Properties {
        private ClientProperties client;
        private ResourceProperties resource;

        @Data
        public class ClientProperties {
            private String clientId;
            private String clientSecret;
            private String registrationId = "tara";
            private String scope;
            private String registeredRedirectUri;
            private String userAuthorizationUri;
            private String accessTokenUri;
        }

        @Data
        public class ResourceProperties {
            private JwkProperties jwk;

            @Data
            public class JwkProperties {
                private String keySetUri;
            }
        }
    }

    @Data
    public class AllowlistProperties {
        private String jwt;
    }
}
