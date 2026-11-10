package com.d10g.ecommerce_auth.application.account;

import com.d10g.ecommerce_auth.domain.account.Account;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Required atomic operations. Implementations participate in the unit of work's transaction.
 */
public interface AccountPorts {
    default void audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType event, UUID userId) {
    }

    <T> T inTransaction(Supplier<T> work);

    /**
     * Serialize matching identifiers and lock existing candidate users in stable ID order.
     */
    void lockRegistration(String username, String email);

    Instant databaseTime();

    Optional<Account> lockById(UUID id);

    /**
     * Called after locking the user; returns only the user's active session at the current auth version.
     */
    Optional<SessionAuthentication> lockAuthenticatedSession(UUID userId, UUID sessionId, long authVersion);

    Optional<Account> lockByUsername(String username);

    Optional<Account> lockByEmail(String email);

    void deleteExpiredPending(Account account);

    void insertPending(UUID id, String username, String email, String passwordHash, Instant now, Instant expiry);

    Optional<Challenge> findChallenge(String tokenHash, Purpose purpose);

    Optional<Challenge> lockChallenge(UUID challengeId);

    void supersedeChallenges(UUID userId, Purpose purpose, Instant now);

    void insertChallenge(UUID id, UUID userId, Purpose purpose, String tokenHash, long authVersion, Instant now, Instant expiry);

    void consumeChallenge(UUID id, Instant now);

    void markEmailVerified(UUID userId, Instant now);

    /**
     * Update password, increment auth version, use database clock_timestamp after user lock, revoke all sessions.
     */
    void changePasswordAndRevoke(UUID userId, String hash);

    /**
     * Enqueue an encrypted payload in the same transaction as its challenge.
     */
    void enqueueEmail(UUID challengeId, UUID userId, String email, Purpose purpose, String token, Instant expiry);

    void insertUserRole(UUID userId);

    String hashPassword(String password);

    boolean passwordMatches(String password, String passwordHash);

    String newToken();

    String hashToken(String token);

    enum Purpose {VERIFY_EMAIL, RESET_PASSWORD}

    record Challenge(UUID id, UUID userId, Purpose purpose, long authVersion, Instant expiresAt,
                     boolean consumed, boolean superseded) {
    }

    record SessionAuthentication(Instant authTime, Instant expiresAt, Instant lastRefreshAt, String authenticationMethod) {
    }

    final class RegistrationConflict extends RuntimeException {
        public RegistrationConflict(Throwable cause) {
            super(cause);
        }
    }
}
