package com.d10g.ecommerce_auth.application.session;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * External dependencies of the session use cases. None of these contracts depend on Spring.
 */
public final class SessionPorts {
    private SessionPorts() {
    }

    public enum Platform {WEB, ANDROID, IOS}

    /**
     * Executes work atomically. An ordinary return, including a rejection outcome, commits.
     */
    public interface Transaction {
        <T> T execute(Supplier<T> work);
    }

    public interface Store {
        /**
         * Resolve the credential and lock the context (WEB), user, session and token, in that
         * order. Re-read every row under lock. A missing credential returns null. A context
         * secret must be checked against the stored hash, not trusted as an identifier.
         */
        LockedCredential lockCredential(byte[] tokenHash, Client client);

        void rotate(LockedCredential credential, UUID tokenId, byte[] tokenHash, Instant now);

        void revoke(LockedCredential credential, Instant now, String reason);

        /**
         * Read from the primary database; no active-session cache may be used.
         */
        ActiveSession findActive(UUID userId, UUID sessionId);

        /**
         * Record approximate activity; implementations throttle writes to at most once per minute.
         */
        default void markSeen(UUID userId, UUID sessionId) {
        }
    }

    public interface Secrets {
        String newRefreshToken();

        byte[] hash(String value);
    }

    public interface AccessTokens {
        String sign(ActiveSession session, Instant issuedAt, Instant expiresAt);

        /**
         * Return null for an invalid token. Throw on dependency failures.
         */
        VerifiedAccessToken verify(String token);
    }

    public record SessionMetadata(String deviceLabel, String userAgent, String maskedIp) {
    }

    public record Client(String clientId, Platform platform, byte[] browserContextHash, SessionMetadata metadata) {
        public Client(String clientId, Platform platform, byte[] browserContextHash) {
            this(clientId, platform, browserContextHash, null);
        }

        public Client {
            if (clientId == null || clientId.isBlank() || platform == null)
                throw new IllegalArgumentException("client required");
            browserContextHash = browserContextHash == null ? null : browserContextHash.clone();
        }

        @Override
        public byte[] browserContextHash() {
            return browserContextHash == null ? null : browserContextHash.clone();
        }
    }

    public record ActiveSession(UUID userId, UUID sessionId, String clientId, Platform platform,
                                long authVersion, Instant authTime, String authenticationMethod,
                                Instant expiresAt, Instant lastRefreshAt, boolean active,
                                boolean userActive, long currentAuthVersion) {
    }

    public record LockedCredential(ActiveSession session, UUID tokenId, UUID familyId,
                                   Instant tokenExpiresAt, Instant usedAt, Instant revokedAt) {
    }

    public record VerifiedAccessToken(UUID userId, UUID sessionId, long authVersion,
                                      Instant expiresAt) {
    }
}
