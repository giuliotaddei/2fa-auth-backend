package com.giuliotaddei.twofa.backend.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Email obbligatoria")
        @Email(message = "Formato email non valido")
        String email,

        @NotBlank(message = "Password obbligatoria")
        @Size(min = 8, max = 72, message = "La password deve essere tra 8 e 72 caratteri")
        String password
) {}