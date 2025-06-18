package app.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class JwtService {

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.refreshSecret}")
    private String refreshSecretKey;
    @Value("${jwt.expiration}")
    private long expirationTime;
    @Value("${jwt.refreshExpiration}")
    private long refreshExpirationTime;

    private final static String TOKEN_PREFIX = "Bearer ";

    // Generate access token
    public String generateToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        return TOKEN_PREFIX + Jwts
                .builder()
                .subject(userPrincipal.getUsername())
                .claim("tokenType", "accessToken")
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getAccessSigningKey())
                .compact();
    }

    // Generate refresh token
    public String generateRefreshToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + refreshExpirationTime);
        Map<String, String> claims = new HashMap<>();
        claims.put("tokenType", "refreshToken");

        return TOKEN_PREFIX + Jwts
                .builder()
                .subject(userPrincipal.getUsername())
                .claims(claims)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getRefreshSigningKey())
                .compact();
    }

    // Extract username from token (access token by default)
    public Optional<String> usernameFromToken(String token) {
        return usernameFromToken(token, false);
    }

    public Optional<String> usernameFromToken(String token, boolean isRefreshToken) {
        return extractClaims(token, isRefreshToken)
                .map(Claims::getSubject);
    }

    // Validate token (access token by default)
    public boolean isTokenValid(String token) {
        return isTokenValid(token, false);
    }

    public boolean isTokenValid(String token, boolean isRefreshToken) {
        return extractClaims(token, isRefreshToken).isPresent();
    }

    // Extract claims from token
    public Optional<Claims> extractClaims(String token) {
        return extractClaims(token, false);
    }

    public Optional<Claims> extractClaims(String token, boolean isRefreshToken) {
        try {
            var claims = Jwts.parser()
                    .verifyWith(isRefreshToken ? getRefreshSigningKey() : getAccessSigningKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String expectedType = isRefreshToken ? "refreshToken" : "accessToken";
            String actualType = claims.get("tokenType", String.class);

            if (!expectedType.equals(actualType)) {
                return Optional.empty();
            }

            return Optional.of(claims);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // Get access signing key
    private SecretKey getAccessSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Get refresh signing key
    private SecretKey getRefreshSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(refreshSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
