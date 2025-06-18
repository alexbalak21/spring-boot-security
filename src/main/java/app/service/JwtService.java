package app.service;


import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.MacAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
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

    //Generate token
    public String generateToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);
        MacAlgorithm algorithm = Jwts.SIG.HS512;

        return TOKEN_PREFIX + Jwts
                .builder()
                .subject(userPrincipal.getUsername())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getAccessSigningKey())
                .compact();
    }

    //GENERATE REFRESH TOKEN
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

    private SecretKey getAccessSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private SecretKey getRefreshSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(refreshSecretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public Optional<String> usernameFromAccessToken(String token) {
        try {
            return Optional.of(
                    Jwts.parser()
                            .verifyWith(getAccessSigningKey())
                            .build()
                            .parseSignedClaims(token)
                            .getPayload()
                            .getSubject()
            );
        } catch (Exception e) {
            return Optional.empty(); // Signature invalid, token expired, etc.
        }
    }

    //USERNAME FROM REFRESH TOKEN
    public Optional<String> usernameFromRefreshToken(String refreshToken) {
        try {
            return Optional.of(
                    Jwts.parser()
                            .verifyWith(getRefreshSigningKey())
                            .build()
                            .parseSignedClaims(refreshToken)
                            .getPayload()
                            .getSubject()
            );
        } catch (Exception e) {
            return Optional.empty(); // Signature invalid, token expired, etc.
        }
    }

    public boolean isAccessTokenValid(String token) {
        try {
            Jwts.parser()
                    .verifyWith(getAccessSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //IS REFRESH TOKEN VALID
    public boolean isRefreshTokenValid(String RefreshToken) {
        try {
            Jwts.parser()
                    .verifyWith(getRefreshSigningKey())
                    .build()
                    .parseSignedClaims(RefreshToken);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
