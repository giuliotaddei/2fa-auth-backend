package com.giuliotaddei.twofa.backend.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyTotpRequest(
        @NotBlank(message = "Token temporaneo obbligatorio")
        String tempToken,

        @NotBlank(message = "Codice TOTP obbligatorio")
        @Pattern(regexp = "\\d{6}", message = "Il codice TOTP deve essere di 6 cifre")
        String totpCode
) {}
