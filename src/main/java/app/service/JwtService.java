package app.service;

import app.config.JwtProperties;
import org.springframework.beans.factory.annotation.Value;

public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.refreshSecret}")
    private String refreshSecretKey;
    @Value("${jwt.expiration}")
    private long expirationTime;
    @Value("${jwt.refreshExpiration}")
    private long refreshExpirationTime;

    private final String TOKEN_PREFIX = "Bearer ";

}
