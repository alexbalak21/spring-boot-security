package app.service;

import app.dto.TokenPair;
import app.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Service
@Slf4j
public class JwtService {

    @Value("${app.jwt.authSecret}")
    private String secretKey;
    @Value("${app.jwt.refreshSecret}")
    private String refreshSecretKey;
    @Value("${app.jwt.AuthExpiration}")
    private long expirationTime;
    @Value("${app.jwt.refreshExpiration}")
    private long refreshExpirationTime;

    private final static String TOKEN_PREFIX = "Bearer ";


    // Generate access token
    public String generateAccessToken(Authentication authentication) {
        UserDetails userPrincipal = (UserDetails) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationTime);

        return TOKEN_PREFIX + Jwts.builder()
                .header()
                .add("typ", "JWT")
                .and()
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

    //
    public boolean validateToken(String token, UserDetails userDetails) {
        try {
            //IF TOKEN IS VALID
            if (usernameFromToken(token).isPresent()) {
                //IF TOKEN BELONGS TO RIGHT USER
                return usernameFromToken(token).get().equals(userDetails.getUsername());
            }
            return false;
        }
        catch (Exception e) {
            return false;
        }
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
        }catch (SignatureException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        }catch (MalformedJwtException e) {
            log.error("Invalid JWT token: {}", e.getMessage());
        }catch (ExpiredJwtException e) {
            log.error("JWT token is expired: {}", e.getMessage());
        }catch (UnsupportedJwtException e) {
            log.error("User not found: {}", e.getMessage());
        }catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return Optional.empty();
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

    public TokenPair generateTokenPair(Authentication authentication) {
        String accessToken = generateAccessToken(authentication);
        String refreshToken = generateRefreshToken(authentication);
        return new TokenPair(accessToken, refreshToken);
    }
}
