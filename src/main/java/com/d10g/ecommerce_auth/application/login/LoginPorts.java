package com.d10g.ecommerce_auth.application.login;

import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.domain.account.Account;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Login dependencies; implementations must be shared by all service instances.
 */
public interface LoginPorts {
    default void audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType event, UUID userId,
                       com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome outcome) {
    }

    <T> T inTransaction(Supplier<T> work);

    /**
     * Returns user and password hash/version from the same database snapshot.
     */
    User findUser(String normalizedUsername);

    /**
     * Locks context first for web, then user, and rereads user under lock.
     */
    User lockUserForLogin(UUID userId, Client client);

    /**
     * Locks context, relevant users in ID order, then challenge; validates client and binding.
     */
    Challenge lockChallenge(UUID challengeId, Client client, String nativeBinding);

    Instant now();

    boolean passwordMatches(String password, String hash);

    String dummyPasswordHash();

    String newNativeBinding();

    String newOtp();

    byte[] otpMac(UUID challengeId, int generation, String otp);

    boolean constantTimeEquals(byte[] first, byte[] second);

    /** Persist the native device ID with the challenge so verification cannot substitute another device. */
    void createChallenge(UUID challengeId, User user, Client client, String nativeBinding, byte[] mac, Instant now, Instant expiresAt, String deviceId);

    /** The caller holds the login locks; unrecognized or expired proof returns false. */
    boolean isTrusted(User user, Client client, String deviceId, String deviceSecret, Instant now);

    /** Replace the appropriate session and issue credentials with password-only authentication. */
    Tokens completeTrusted(User user, Client client, Instant now);

    /** Remember only the device captured with this verified challenge. Returns a native secret if applicable. */
    String rememberDevice(Challenge challenge, Client client, Instant now, Instant expiresAt);

    void enqueueOtp(Challenge challenge, String otp, Instant now);

    void incrementAttempts(Challenge challenge);

    void resendOtp(Challenge challenge, byte[] mac, Instant now, Instant expiresAt);

    /**
     * Consume challenge, replace affected sessions, and sign tokens in this same transaction.
     */
    Tokens complete(Challenge challenge, Client client, Instant now);

    /**
     * Fail closed by throwing a dependency error when Redis is unavailable.
     */
    void checkPasswordLimit(String normalizedUsername, String ip);

    void recordPasswordFailure(String normalizedUsername, String ip);

    default void passwordSucceeded() {
    }

    void checkOtpLimit(UUID userId, UUID challengeId);

    void recordOtpFailure(UUID userId, UUID challengeId);

    default void otpSucceeded() {
    }

    void checkMailLimit(UUID userId);

    record User(UUID id, String username, String email, String passwordHash, long authVersion,
                Account.Status status, boolean emailVerified) {
    }

    record Challenge(UUID id, User user, String clientId, long authVersion, byte[] otpMac, int generation,
                     int attempts, Instant expiresAt, Instant lastSentAt, boolean consumed, boolean superseded) {
    }

    record Tokens(String accessToken, String refreshToken, UUID sessionId, long expiresIn) {
    }
}
