package com.giuliotaddei.twofa.backend.dto.response;

public record TotpSetupResponse(
        String qrCodeUri,   // URI per generare il QR code lato frontend
        String manualKey    // chiave manuale per chi non può scansionare il QR
) {}
