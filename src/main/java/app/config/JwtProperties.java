package app.config;


import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(JwtProperties.class)
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    private final String secret;
    private final String refreshTokenSecret;
    private final long expiration;
    private final long refreshTokenExpiration;

    public JwtProperties(String secret, String refreshTokenSecret, long expiration, long refreshTokenExpiration) {
        this.secret = secret;
        this.refreshTokenSecret = refreshTokenSecret;
        this.expiration = expiration;
        this.refreshTokenExpiration = refreshTokenExpiration;
    }

    public String getSecret() {
        return secret;
    }

    public String getRefreshTokenSecret() {
        return refreshTokenSecret;
    }

    public long getExpiration() {
        return expiration;
    }

    public long getRefreshTokenExpiration() {
        return refreshTokenExpiration;
    }
}