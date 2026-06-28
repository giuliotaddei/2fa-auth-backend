package com.giuliotaddei.twofa.backend.service;

import com.giuliotaddei.twofa.backend.entity.RefreshToken;
import com.giuliotaddei.twofa.backend.entity.User;
import com.giuliotaddei.twofa.backend.exception.TokenException;
import com.giuliotaddei.twofa.backend.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    /**
     * Crea un nuovo refresh token per l'utente.
     * Il token grezzo viene restituito al client, ma nel DB salviamo solo il suo hash SHA-256.
     * Così anche se il DB venisse compromesso, i token non sarebbero utilizzabili.
     */
    @Transactional
    public String createRefreshToken(User user) {
        String rawToken = generateSecureToken();
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(tokenHash)
                .expiresAt(LocalDateTime.now().plusSeconds(refreshExpirationMs / 1000))
                .build();

        refreshTokenRepository.save(refreshToken);
        return rawToken; // restituiamo il token grezzo, non l'hash
    }

    /**
     * Valida un refresh token e restituisce l'utente associato.
     * Dopo la validazione il token viene ruotato (deleted + nuovo creato) per sicurezza.
     */
    @Transactional
    public User validateAndRotate(String rawToken) {
        String tokenHash = hashToken(rawToken);

        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new TokenException("Refresh token non valido"));

        if (refreshToken.isExpired()) {
            refreshTokenRepository.delete(refreshToken);
            throw new TokenException("Refresh token scaduto");
        }

        User user = refreshToken.getUser();
        // Rotazione: invalida il vecchio token
        refreshTokenRepository.delete(refreshToken);
        return user;
    }

    /**
     * Invalida tutti i refresh token dell'utente (usato al logout).
     */
    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.deleteAllByUser(user);
    }

    /**
     * Pulizia automatica dei token scaduti ogni 24 ore.
     */
    @Scheduled(fixedRate = 86_400_000)
    @Transactional
    public void cleanupExpiredTokens() {
        refreshTokenRepository.deleteAllExpired(LocalDateTime.now());
    }

    // ── Metodi privati ────────────────────────────────────────────────────────

    private String generateSecureToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Errore hashing token", e);
        }
    }
}