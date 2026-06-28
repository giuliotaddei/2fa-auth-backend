package com.giuliotaddei.twofa.backend.service;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import org.springframework.stereotype.Service;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import javax.imageio.ImageIO;

/**
 * Gestisce la generazione e verifica dei codici TOTP
 * compatibili con Google Authenticator e Authy.
 */
@Service
public class TotpService {

    private static final String ISSUER = "2FA-Auth-System";
    private static final int QR_WIDTH = 300;
    private static final int QR_HEIGHT = 300;
    // Finestra di tolleranza: accetta codici del periodo precedente/successivo
    // per compensare piccole differenze di orologio tra client e server
    private static final int TIME_WINDOW = 1;

    private final TimeBasedOneTimePasswordGenerator totpGenerator;

    public TotpService() throws Exception {
        this.totpGenerator = new TimeBasedOneTimePasswordGenerator(Duration.ofSeconds(30));
    }

    /**
     * Genera un nuovo secret TOTP casuale (160 bit, standard RFC 4226).
     * Questo viene salvato cifrato nel DB e usato per generare/verificare i codici.
     */
    public String generateSecret() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    totpGenerator.getAlgorithm()
            );
            keyGenerator.init(160, new SecureRandom());
            SecretKey key = keyGenerator.generateKey();
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (Exception e) {
            throw new RuntimeException("Errore generazione secret TOTP", e);
        }
    }

    /**
     * Verifica se il codice OTP inserito dall'utente è valido.
     * Controlla il periodo corrente e quello precedente/successivo (TIME_WINDOW)
     * per tollerare piccole differenze di clock.
     */
    public boolean verifyCode(String base64Secret, String code) {
        try {
            SecretKey key = decodeSecret(base64Secret);
            int inputCode = Integer.parseInt(code);
            Instant now = Instant.now();
            Duration step = totpGenerator.getTimeStep();

            for (int i = -TIME_WINDOW; i <= TIME_WINDOW; i++) {
                Instant timeToCheck = now.plus(step.multipliedBy(i));
                int expectedCode = totpGenerator.generateOneTimePassword(key, timeToCheck);
                if (expectedCode == inputCode) {
                    return true;
                }
            }
            return false;
        } catch (NumberFormatException e) {
            return false; // codice non numerico
        } catch (Exception e) {
            throw new RuntimeException("Errore verifica codice TOTP", e);
        }
    }

    /**
     * Genera l'URI otpauth:// standard per creare il QR code.
     * Questo URI viene scansionato dalle app authenticator.
     */
    public String generateOtpAuthUri(String email, String base64Secret) {
        String secret = encodeToBase32(decodeSecret(base64Secret).getEncoded());
        return String.format(
                "otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
                urlEncode(ISSUER),
                urlEncode(email),
                secret,
                urlEncode(ISSUER)
        );
    }

    /**
     * Genera il QR code come immagine PNG in Base64.
     * Il frontend lo mostrerà direttamente in un <img src="data:image/png;base64,...">
     */
    public String generateQrCodeBase64(String otpAuthUri) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(
                    otpAuthUri, BarcodeFormat.QR_CODE, QR_WIDTH, QR_HEIGHT
            );
            BufferedImage image = MatrixToImageWriter.toBufferedImage(bitMatrix);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ImageIO.write(image, "PNG", outputStream);
            return Base64.getEncoder().encodeToString(outputStream.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Errore generazione QR code", e);
        }
    }

    /**
     * Restituisce la chiave manuale (per chi non può scansionare il QR).
     * È semplicemente il secret in Base32, che l'utente digita manualmente nell'app.
     */
    public String getManualEntryKey(String base64Secret) {
        return encodeToBase32(decodeSecret(base64Secret).getEncoded());
    }

    // ── Metodi privati ────────────────────────────────────────────────────────

    private SecretKey decodeSecret(String base64Secret) {
        byte[] keyBytes = Base64.getDecoder().decode(base64Secret);
        return new SecretKeySpec(keyBytes, totpGenerator.getAlgorithm());
    }

    /**
     * Converte bytes in Base32 (RFC 4648) senza padding.
     * Le app authenticator usano Base32 per i secret TOTP.
     */
    private String encodeToBase32(byte[] data) {
        final String BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(BASE32_CHARS.charAt((buffer >> (bitsLeft - 5)) & 31));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            result.append(BASE32_CHARS.charAt((buffer << (5 - bitsLeft)) & 31));
        }
        return result.toString();
    }

    private String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
