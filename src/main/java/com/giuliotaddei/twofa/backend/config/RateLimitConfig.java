package com.giuliotaddei.twofa.backend.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gestisce i bucket di rate limiting per IP.
 * Ogni IP ha un bucket separato con capacità configurabile.
 * Usa ConcurrentHashMap per thread safety senza sincronizzazione esplicita.
 */
@Component
public class RateLimitConfig {

    private final int capacity;
    private final int refillMinutes;
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public RateLimitConfig(
            @Value("${rate-limit.login.capacity}") int capacity,
            @Value("${rate-limit.login.refill-minutes}") int refillMinutes) {
        this.capacity = capacity;
        this.refillMinutes = refillMinutes;
    }

    /**
     * Restituisce il bucket per l'IP dato, creandolo se non esiste.
     * Esempio con i valori default: 5 richieste ogni 1 minuto per IP.
     */
    public Bucket resolveBucket(String ipAddress) {
        return buckets.computeIfAbsent(ipAddress, this::createNewBucket);
    }

    private Bucket createNewBucket(String ipAddress) {
        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(capacity, Duration.ofMinutes(refillMinutes))
                .build();
        return Bucket.builder()
                .addLimit(limit)
                .build();
    }
}
