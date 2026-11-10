package com.d10g.ecommerce_auth.security.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Generates and fingerprints opaque credentials. Raw credentials must never be logged.
 */
public final class OpaqueSecrets {
    private final SecureRandom random;

    public OpaqueSecrets() {
        this(new SecureRandom());
    }

    OpaqueSecrets(SecureRandom random) {
        this.random = random;
    }

    public String generate() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String randomDigits(int length) {
        if (length < 1 || length > 128) {
            throw new IllegalArgumentException("Invalid digit count");
        }
        StringBuilder value = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            value.append((char) ('0' + random.nextInt(10)));
        }
        return value.toString();
    }

    public byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public byte[] hmacSha256(String value, byte[] key) {
        if (key == null || key.length < 32) {
            throw new IllegalArgumentException("HMAC key must contain at least 256 bits");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    public boolean matches(byte[] expected, byte[] actual) {
        return expected != null && actual != null && MessageDigest.isEqual(expected, actual);
    }
}
