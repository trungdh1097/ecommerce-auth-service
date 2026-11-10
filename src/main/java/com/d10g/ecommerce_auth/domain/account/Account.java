package com.d10g.ecommerce_auth.domain.account;

import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Authentication-owned account state. No transport or persistence dependencies.
 */
public final class Account {
    private static final Pattern USERNAME = Pattern.compile("[a-z0-9._-]{3,50}");
    private final UUID id;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final boolean emailVerified;
    private final Status status;
    private final Instant registrationExpiresAt;
    private final long authVersion;
    public Account(UUID id, String username, String email, String passwordHash, boolean emailVerified,
                   Status status, Instant registrationExpiresAt, long authVersion) {
        this.id = Objects.requireNonNull(id);
        this.username = username;
        this.email = Objects.requireNonNull(email);
        this.passwordHash = passwordHash;
        this.emailVerified = emailVerified;
        this.status = Objects.requireNonNull(status);
        this.registrationExpiresAt = registrationExpiresAt;
        this.authVersion = authVersion;
        if (status == Status.PENDING_VERIFICATION && registrationExpiresAt == null) {
            throw new IllegalArgumentException("Pending registration requires expiry");
        }
    }

    public static String normalizeUsername(String value) {
        String normalized = Objects.requireNonNull(value, "username").trim().toLowerCase(Locale.ROOT);
        if (!USERNAME.matcher(normalized).matches()) throw new IllegalArgumentException("Invalid username");
        return normalized;
    }

    public static String normalizeEmail(String value) {
        String normalized = Objects.requireNonNull(value, "email").trim().toLowerCase(Locale.ROOT);
        if (normalized.length() > 320 || normalized.length() < 3 || normalized.indexOf('@') <= 0
                || normalized.indexOf('@') != normalized.lastIndexOf('@')
                || normalized.endsWith("@") || normalized.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("Invalid email");
        }
        return normalized;
    }

    public static void validatePassword(String password) {
        if (password == null || password.length() < 12 || password.length() > 128)
            throw new IllegalArgumentException("Password length must be 12–128 characters");
    }

    public boolean pendingExpired(Instant now) {
        return status == Status.PENDING_VERIFICATION && !now.isBefore(registrationExpiresAt);
    }

    public boolean mayVerify(Instant now) {
        return status != Status.DISABLED && !pendingExpired(now);
    }

    public boolean mayResetPassword() {
        return status == Status.ACTIVE && emailVerified && passwordHash != null;
    }

    public UUID id() {
        return id;
    }

    public String username() {
        return username;
    }

    public String email() {
        return email;
    }

    public String passwordHash() {
        return passwordHash;
    }

    public boolean emailVerified() {
        return emailVerified;
    }

    public Status status() {
        return status;
    }

    public Instant registrationExpiresAt() {
        return registrationExpiresAt;
    }

    public long authVersion() {
        return authVersion;
    }

    public enum Status {PENDING_VERIFICATION, ACTIVE, DISABLED}
}
