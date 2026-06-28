package com.giuliotaddei.twofa.backend.service;

import com.giuliotaddei.twofa.backend.dto.request.LoginRequest;
import com.giuliotaddei.twofa.backend.dto.request.RegisterRequest;
import com.giuliotaddei.twofa.backend.dto.request.VerifyTotpRequest;
import com.giuliotaddei.twofa.backend.dto.response.AuthResponse;
import com.giuliotaddei.twofa.backend.dto.response.TotpSetupResponse;
import com.giuliotaddei.twofa.backend.entity.User;
import com.giuliotaddei.twofa.backend.exception.AuthException;
import com.giuliotaddei.twofa.backend.repository.UserRepository;
import com.giuliotaddei.twofa.backend.security.jwt.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 15;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final TotpService totpService;
    private final EncryptionService encryptionService;
    private final RefreshTokenService refreshTokenService;

    @Value("${jwt.expiration-ms}")
    private long accessExpirationMs;

    // ── Registrazione ─────────────────────────────────────────────────────────

    /**
     * Step 1 della registrazione: crea l'utente e genera il secret TOTP.
     * Restituisce il QR code da mostrare all'utente per configurare l'app authenticator.
     */
    @Transactional
    public TotpSetupResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new AuthException("Email già registrata");
        }

        String totpSecret = totpService.generateSecret();
        String encryptedSecret = encryptionService.encrypt(totpSecret);

        User user = User.builder()
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .totpSecret(encryptedSecret)
                .totpEnabled(false)
                .build();

        userRepository.save(user);
        log.info("Nuovo utente registrato: {}", request.email());

        String otpAuthUri = totpService.generateOtpAuthUri(request.email(), totpSecret);
        String qrCodeBase64 = totpService.generateQrCodeBase64(otpAuthUri);
        String manualKey = totpService.getManualEntryKey(totpSecret);

        return new TotpSetupResponse(qrCodeBase64, manualKey);
    }

    /**
     * Step 2 della registrazione: l'utente scansiona il QR e inserisce il primo codice
     * per confermare che l'app authenticator è configurata correttamente.
     */
    @Transactional
    public void confirmTotpSetup(String email, String totpCode) {
        User user = findUserByEmail(email);

        if (user.isTotpEnabled()) {
            throw new AuthException("TOTP già configurato per questo utente");
        }

        String decryptedSecret = encryptionService.decrypt(user.getTotpSecret());
        if (!totpService.verifyCode(decryptedSecret, totpCode)) {
            throw new AuthException("Codice TOTP non valido");
        }

        user.setTotpEnabled(true);
        userRepository.save(user);
        log.info("TOTP abilitato per: {}", email);
    }

    // ── Login ─────────────────────────────────────────────────────────────────

    /**
     * Step 1 del login: verifica email e password.
     * Se corrette, emette un temp token (valido 5 min) da usare per il verify-totp.
     * Non emette ancora l'access token definitivo.
     */
    @Transactional
    public String loginStepOne(LoginRequest request) {
        User user = findUserByEmail(request.email());

        checkAccountLocked(user);

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            handleFailedAttempt(user);
            throw new AuthException("Credenziali non valide");
        }

        if (!user.isTotpEnabled()) {
            throw new AuthException("TOTP non configurato. Completa la registrazione prima.");
        }

        // Login step 1 riuscito: reset tentativi falliti, emetti temp token
        userRepository.resetFailedAttemptsAndUpdateLogin(user.getId(), LocalDateTime.now());
        log.info("Login step 1 completato per: {}", request.email());

        return jwtService.generateTempToken(request.email());
    }

    /**
     * Step 2 del login: verifica il codice TOTP usando il temp token ottenuto al step 1.
     * Se valido, emette l'access token definitivo + refresh token.
     */
    @Transactional
    public AuthResponse loginStepTwo(VerifyTotpRequest request) {
        String email = jwtService.validateTempTokenAndGetEmail(request.tempToken());
        User user = findUserByEmail(email);

        String decryptedSecret = encryptionService.decrypt(user.getTotpSecret());
        if (!totpService.verifyCode(decryptedSecret, request.totpCode())) {
            throw new AuthException("Codice TOTP non valido");
        }

        String accessToken = jwtService.generateAccessToken(email);
        String refreshToken = refreshTokenService.createRefreshToken(user);
        log.info("Login completato per: {}", email);

        return AuthResponse.of(accessToken, refreshToken, accessExpirationMs / 1000);
    }

    // ── Refresh e Logout ──────────────────────────────────────────────────────

    /**
     * Rinnova l'access token usando il refresh token.
     * Il refresh token viene ruotato ad ogni uso (token rotation).
     */
    @Transactional
    public AuthResponse refresh(String rawRefreshToken) {
        User user = refreshTokenService.validateAndRotate(rawRefreshToken);
        String newAccessToken = jwtService.generateAccessToken(user.getEmail());
        String newRefreshToken = refreshTokenService.createRefreshToken(user);

        return AuthResponse.of(newAccessToken, newRefreshToken, accessExpirationMs / 1000);
    }

    /**
     * Invalida tutti i refresh token dell'utente (logout da tutti i dispositivi).
     */
    @Transactional
    public void logout(String email) {
        User user = findUserByEmail(email);
        refreshTokenService.revokeAllUserTokens(user);
        log.info("Logout effettuato per: {}", email);
    }

    // ── Metodi privati ────────────────────────────────────────────────────────

    private User findUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("Credenziali non valide"));
    }

    private void checkAccountLocked(User user) {
        if (user.isLocked()) {
            throw new AuthException(
                    "Account temporaneamente bloccato. Riprova tra " + LOCK_DURATION_MINUTES + " minuti."
            );
        }
    }

    private void handleFailedAttempt(User user) {
        userRepository.incrementFailedAttempts(user.getId());
        int attempts = user.getFailedAttempts() + 1;

        if (attempts >= MAX_FAILED_ATTEMPTS) {
            userRepository.lockUser(
                    user.getId(),
                    LocalDateTime.now().plusMinutes(LOCK_DURATION_MINUTES)
            );
            log.warn("Account bloccato per troppi tentativi falliti: {}", user.getEmail());
            throw new AuthException(
                    "Troppi tentativi falliti. Account bloccato per " + LOCK_DURATION_MINUTES + " minuti."
            );
        }
    }
}