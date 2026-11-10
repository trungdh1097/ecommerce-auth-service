package com.d10g.ecommerce_auth.adapter.out.notification;

import java.net.URI;
import java.util.Objects;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

/**
 * Formats secret-bearing email without putting credentials into query strings.
 */
public final class EmailNotificationSender {
    private final JavaMailSender mail;
    private final String from;
    private final URI verifyUrl;
    private final URI resetUrl;

    public EmailNotificationSender(JavaMailSender mail, String from, String verifyUrl, String resetUrl) {
        this.mail = Objects.requireNonNull(mail);
        if (from == null || from.isBlank() || from.contains("\n") || from.contains("\r"))
            throw new IllegalArgumentException("Sender required");
        this.from = from;
        this.verifyUrl = frontendUrl(verifyUrl);
        this.resetUrl = frontendUrl(resetUrl);
    }

    private static URI frontendUrl(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Frontend URL required");
        URI uri = URI.create(value);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null || uri.getFragment() != null) {
            throw new IllegalArgumentException("Frontend URL must be HTTPS without user info or fragment");
        }
        return uri;
    }

    private static String link(URI uri, String token) {
        if (!token.matches("[A-Za-z0-9_-]+")) throw new IllegalArgumentException("Invalid token payload");
        return uri.toASCIIString() + "#token=" + token;
    }

    public void send(String purpose, String email, String secret) {
        if (email == null || email.isBlank() || email.contains("\n") || email.contains("\r") || secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("Invalid notification payload");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(email);
        switch (purpose) {
            case "VERIFY_EMAIL" -> {
                message.setSubject("Verify your email");
                message.setText("Open this link to verify your email: " + link(verifyUrl, secret));
            }
            case "RESET_PASSWORD" -> {
                message.setSubject("Reset your password");
                message.setText("Open this link to reset your password: " + link(resetUrl, secret));
            }
            case "LOGIN_OTP" -> {
                if (!secret.matches("[0-9]{6}")) throw new IllegalArgumentException("Invalid OTP payload");
                message.setSubject("Your login code");
                message.setText("Your login code is " + secret + ". It expires in five minutes.");
            }
            default -> throw new IllegalArgumentException("Invalid notification purpose");
        }
        mail.send(message);
    }
}
