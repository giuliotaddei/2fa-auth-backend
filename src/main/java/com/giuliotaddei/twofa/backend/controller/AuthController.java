package com.giuliotaddei.twofa.backend.controller;

import com.giuliotaddei.twofa.backend.dto.request.LoginRequest;
import com.giuliotaddei.twofa.backend.dto.request.RegisterRequest;
import com.giuliotaddei.twofa.backend.dto.request.VerifyTotpRequest;
import com.giuliotaddei.twofa.backend.dto.response.AuthResponse;
import com.giuliotaddei.twofa.backend.dto.response.TotpSetupResponse;
import com.giuliotaddei.twofa.backend.service.AuthService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/register
     * Registra un nuovo utente e restituisce il QR code per configurare il TOTP.
     *
     * Body: { "email": "...", "password": "..." }
     * Response: { "qrCodeUri": "data:image/png;base64,...", "manualKey": "ABCD1234..." }
     */
    @PostMapping("/register")
    public ResponseEntity<TotpSetupResponse> register(@Valid @RequestBody RegisterRequest request) {
        TotpSetupResponse response = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * POST /api/auth/register/confirm-totp
     * Conferma la configurazione del TOTP dopo la registrazione.
     * L'utente scansiona il QR e inserisce il primo codice per verificare che tutto funzioni.
     *
     * Body: { "email": "...", "totpCode": "123456" }
     */
    @PostMapping("/register/confirm-totp")
    public ResponseEntity<Map<String, String>> confirmTotpSetup(
            @RequestBody @Valid ConfirmTotpSetupRequest request) {
        authService.confirmTotpSetup(request.email(), request.totpCode());
        return ResponseEntity.ok(Map.of("message", "TOTP configurato con successo. Puoi ora effettuare il login."));
    }

    /**
     * POST /api/auth/login
     * Step 1 del login: verifica email e password.
     * Restituisce un temp token da usare per il verify-totp.
     *
     * Body: { "email": "...", "password": "..." }
     * Response: { "tempToken": "..." }
     */
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@Valid @RequestBody LoginRequest request) {
        String tempToken = authService.loginStepOne(request);
        return ResponseEntity.ok(Map.of("tempToken", tempToken));
    }

    /**
     * POST /api/auth/verify-totp
     * Step 2 del login: verifica il codice TOTP.
     * Restituisce l'access token + refresh token definitivi.
     *
     * Body: { "tempToken": "...", "totpCode": "123456" }
     * Response: { "accessToken": "...", "refreshToken": "...", "tokenType": "Bearer", "expiresIn": 900 }
     */
    @PostMapping("/verify-totp")
    public ResponseEntity<AuthResponse> verifyTotp(@Valid @RequestBody VerifyTotpRequest request) {
        AuthResponse response = authService.loginStepTwo(request);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /api/auth/refresh
     * Rinnova l'access token usando il refresh token.
     *
     * Body: { "refreshToken": "..." }
     * Response: { "accessToken": "...", "refreshToken": "...", ... }
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            @RequestBody Map<String, @NotBlank String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(authService.refresh(refreshToken));
    }

    /**
     * POST /api/auth/logout
     * Invalida tutti i refresh token dell'utente corrente.
     * Richiede JWT valido nell'header Authorization.
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @AuthenticationPrincipal UserDetails userDetails) {
        authService.logout(userDetails.getUsername());
        return ResponseEntity.ok(Map.of("message", "Logout effettuato con successo"));
    }

    // ── Record interni al controller ──────────────────────────────────────────

    record ConfirmTotpSetupRequest(
            @NotBlank String email,
            @NotBlank String totpCode
    ) {}
}
