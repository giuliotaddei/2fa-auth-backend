package com.giuliotaddei.twofa.backend.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;

/**
 * Gestisce la creazione e validazione dei JWT.
 *
 * Abbiamo due tipi di token:
 * - Access token: JWT completo, vita breve (15 min), usato per autenticare le richieste
 * - Temp token: JWT con claim "type=temp", vita brevissima (5 min),
 *   emesso dopo login step 1 (email+psw ok) e usato solo per il verify-totp
 */
@Service
public class JwtService {

    private static final String CLAIM_TYPE = "type";
    private static final String TYPE_TEMP = "temp";
    private static final String TYPE_ACCESS = "access";

    private final SecretKey signingKey;
    private final long accessExpirationMs;
    private final long tempExpirationMs;

    public JwtService(
            @Value("${jwt.secret}") String base64Secret,
            @Value("${jwt.expiration-ms}") long accessExpirationMs,
            @Value("${jwt.temp-expiration-ms}") long tempExpirationMs) {

        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        this.accessExpirationMs = accessExpirationMs;
        this.tempExpirationMs = tempExpirationMs;
    }

    // ── Generazione token ─────────────────────────────────────────────────────

    /**
     * Token temporaneo emesso dopo verifica email+password.
     * Contiene solo l'email e il flag "type=temp".
     * Il frontend lo usa esclusivamente per chiamare /verify-totp.
     */
    public String generateTempToken(String email) {
        return buildToken(email, tempExpirationMs, Map.of(CLAIM_TYPE, TYPE_TEMP));
    }

    /**
     * Access token definitivo emesso dopo verifica TOTP.
     * Questo è il JWT che il frontend include in ogni richiesta autenticata.
     */
    public String generateAccessToken(String email) {
        return buildToken(email, accessExpirationMs, Map.of(CLAIM_TYPE, TYPE_ACCESS));
    }

    // ── Validazione token ─────────────────────────────────────────────────────

    /**
     * Valida un access token. Lancia eccezione se non valido o scaduto.
     */
    public String validateAccessTokenAndGetEmail(String token) {
        Claims claims = parseClaims(token);
        if (!TYPE_ACCESS.equals(claims.get(CLAIM_TYPE))) {
            throw new JwtException("Token non è un access token");
        }
        return claims.getSubject();
    }

    /**
     * Valida un temp token e restituisce l'email.
     */
    public String validateTempTokenAndGetEmail(String token) {
        Claims claims = parseClaims(token);
        if (!TYPE_TEMP.equals(claims.get(CLAIM_TYPE))) {
            throw new JwtException("Token non è un temp token");
        }
        return claims.getSubject();
    }

    public boolean isTokenValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // ── Metodi privati ────────────────────────────────────────────────────────

    private String buildToken(String subject, long expirationMs, Map<String, ?> extraClaims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(subject)
                .claims(extraClaims)
                .issuedAt(new Date(now))
                .expiration(new Date(now + expirationMs))
                .signWith(signingKey)
                .compact();
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
