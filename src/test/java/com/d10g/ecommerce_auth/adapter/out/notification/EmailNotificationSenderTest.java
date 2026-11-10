package com.d10g.ecommerce_auth.adapter.out.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;

class EmailNotificationSenderTest {
    static class CaptureMail extends JavaMailSenderImpl {
        SimpleMailMessage sent;
        @Override public void send(SimpleMailMessage message) { sent = message; }
    }

    @Test void putsOneTimeTokensInFragmentAndKeepsOtpAsDigits() {
        CaptureMail mail = new CaptureMail();
        EmailNotificationSender sender = new EmailNotificationSender(mail, "sender@example.test",
                "https://example.test/verify", "https://example.test/reset");
        sender.send("VERIFY_EMAIL", "a@example.test", "abc_-123");
        assertTrue(mail.sent.getText().contains("https://example.test/verify#token=abc_-123"));
        sender.send("RESET_PASSWORD", "a@example.test", "abc123");
        assertTrue(mail.sent.getText().contains("https://example.test/reset#token=abc123"));
        sender.send("LOGIN_OTP", "a@example.test", "000123");
        assertTrue(mail.sent.getText().contains("000123"));
        assertThrows(IllegalArgumentException.class, () -> sender.send("LOGIN_OTP", "a@example.test", "123"));
        assertThrows(IllegalArgumentException.class, () -> sender.send("VERIFY_EMAIL", "a@example.test", "bad&value"));
        assertThrows(IllegalArgumentException.class, () -> new EmailNotificationSender(mail, "sender@example.test",
                "http://example.test/verify", "https://example.test/reset"));
    }

    @Test void keyRingSupportsOldKeysAndRequiresAnActiveKey() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        OutboxKeyRing ring = new OutboxKeyRing("new", Map.of("old", key, "new", key));
        assertEquals("new", ring.activeKeyId());
        assertNotNull(ring.cipher("old"));
        assertNull(ring.cipher("missing"));
        assertThrows(IllegalArgumentException.class, () -> new OutboxKeyRing("missing", Map.of("old", key)));
    }
}
