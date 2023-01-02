package ee.eesti.authentication.configuration;

import org.mockito.Mockito;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.jwt.JwtDecoder;

@Configuration
@Profile("mock")
public class TestProfileConfiguration {

    @Bean
    @Primary
    public OAuth2AccessTokenResponseClient<?> mockedAccessTokenResponseClient() {
        return Mockito.mock(OAuth2AccessTokenResponseClient.class);
    }

    @Bean
    @Primary
    public JwtDecoder jwtDecoder() {
        return Mockito.mock(JwtDecoder.class);
    }
}
