package com.d10g.ecommerce_auth.security.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM encrypted payload. The key ID is stored separately with the payload.
 */
public final class OutboxCipher {
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final SecretKeySpec key;
    private final SecureRandom random;

    public OutboxCipher(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("Outbox key must contain 256 bits");
        }
        this.key = new SecretKeySpec(key.clone(), "AES");
        this.random = new SecureRandom();
    }

    /**
     * Returns nonce followed by ciphertext and authentication tag.
     */
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
            if (associatedData != null) cipher.updateAAD(associatedData);
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] result = Arrays.copyOf(nonce, nonce.length + ciphertext.length);
            System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
            return result;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Unable to encrypt outbox payload", e);
        }
    }

    public byte[] decrypt(byte[] payload, byte[] associatedData) throws GeneralSecurityException {
        if (payload == null || payload.length < NONCE_BYTES + TAG_BITS / 8) {
            throw new GeneralSecurityException("Invalid encrypted payload");
        }
        byte[] nonce = Arrays.copyOf(payload, NONCE_BYTES);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, nonce));
        if (associatedData != null) cipher.updateAAD(associatedData);
        return cipher.doFinal(payload, NONCE_BYTES, payload.length - NONCE_BYTES);
    }
}
