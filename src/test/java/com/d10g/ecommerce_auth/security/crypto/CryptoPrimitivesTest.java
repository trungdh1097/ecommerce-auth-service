package com.d10g.ecommerce_auth.security.crypto;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class CryptoPrimitivesTest {
    @Test
    void opaqueTokensAndOtpHaveRequiredShape() {
        OpaqueSecrets secrets = new OpaqueSecrets();
        String first = secrets.generate();
        assertEquals(32, Base64.getUrlDecoder().decode(first).length);
        assertNotEquals(first, secrets.generate());
        assertTrue(secrets.randomDigits(6).matches("[0-9]{6}"));
        assertTrue(secrets.matches(secrets.sha256(first), secrets.sha256(first)));
        assertFalse(secrets.matches(secrets.sha256(first), secrets.sha256("other")));
        assertThrows(IllegalArgumentException.class, () -> secrets.hmacSha256("123456", new byte[16]));
    }

    @Test
    void encryptedOutboxPayloadIsAuthenticated() throws GeneralSecurityException {
        OutboxCipher cipher = new OutboxCipher(new byte[32]);
        byte[] data = "sensitive message".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "challenge:generation".getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.encrypt(data, aad);
        assertArrayEquals(data, cipher.decrypt(encrypted, aad));
        assertFalse(java.util.Arrays.equals(encrypted, cipher.encrypt(data, aad)));
        assertThrows(GeneralSecurityException.class, () -> cipher.decrypt(encrypted, new byte[0]));
        encrypted[encrypted.length - 1] ^= 1;
        assertThrows(GeneralSecurityException.class, () -> cipher.decrypt(encrypted, aad));
    }
}
