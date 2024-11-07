package org.ddanzit.common.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

@Component
@Slf4j
public class JwtUtils {

    private SecretKey secretKey;
    @Value("${jwt.access_token.life_time}")
    private Long accessTokenLifeTime;
    @Value("${jwt.refresh_token.life_time}")
    private Long refreshTokenLifeTime;


    @Autowired
    public JwtUtils(@Value("${jwt.secret}") String secret) {
        Keys.hmacShaKeyFor(Base64.getEncoder().encode(secret.getBytes()));
    }


    public String createToken(Date expiration) {
        return Jwts.builder()
                .expiration(expiration)
                .signWith(secretKey)
                .compact();
    }

    public Claims getTokenPayload(String token) {

        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException e) {
            throw new RuntimeException(e);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean validateToken(String token) {
        try {
            getTokenPayload(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


}
