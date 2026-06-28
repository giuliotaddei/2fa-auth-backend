package com.giuliotaddei.twofa.backend.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cifra e decifra dati sensibili con AES-256-GCM.
 * GCM è preferito rispetto a CBC perché fornisce anche autenticazione
 * del testo cifrato (impedisce manomissioni).
 */
@Service
public class EncryptionService {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int GCM_IV_LENGTH = 12;   // 96 bit, raccomandato per GCM
    private static final int GCM_TAG_LENGTH = 128;  // bit di autenticazione

    private final SecretKey secretKey;

    public EncryptionService(@Value("${encryption.key}") String base64Key) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        if (keyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "La chiave AES deve essere 32 byte (256 bit). " +
                            "Generala con: openssl rand -base64 32"
            );
        }
        this.secretKey = new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Cifra una stringa. Il risultato include IV + ciphertext in Base64,
     * separati da ":" per poter decifrare senza salvare l'IV separatamente.
     */
    public String encrypt(String plaintext) {
        try {
            byte[] iv = generateIv();
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes());

            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String encryptedBase64 = Base64.getEncoder().encodeToString(encrypted);
            return ivBase64 + ":" + encryptedBase64;
        } catch (Exception e) {
            throw new RuntimeException("Errore durante la cifratura", e);
        }
    }

    /**
     * Decifra una stringa cifrata con encrypt().
     */
    public String decrypt(String encryptedData) {
        try {
            String[] parts = encryptedData.split(":");
            if (parts.length != 2) {
                throw new IllegalArgumentException("Formato dati cifrati non valido");
            }
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] encrypted = Base64.getDecoder().decode(parts[1]);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH, iv));
            return new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            throw new RuntimeException("Errore durante la decifratura", e);
        }
    }

    private byte[] generateIv() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        return iv;
    }
}
