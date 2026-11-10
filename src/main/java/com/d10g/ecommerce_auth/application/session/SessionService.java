package com.d10g.ecommerce_auth.application.session;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

import com.d10g.ecommerce_auth.application.observability.AuthMetrics;

/**
 * Session credential operations. Rejected outcomes are returned, never thrown, when changes must commit.
 */
public final class SessionService {
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(5);
    private static final Duration IDLE_LIFETIME = Duration.ofDays(7);
    private final Transaction transaction;
    private final Store store;
    private final Secrets secrets;
    private final AccessTokens accessTokens;
    private final Clock clock;
    private final AuthMetrics metrics;

    public SessionService(Transaction transaction, Store store, Secrets secrets, AccessTokens accessTokens, Clock clock) {
        this(transaction, store, secrets, accessTokens, clock, AuthMetrics.NOOP);
    }

    public SessionService(Transaction transaction, Store store, Secrets secrets, AccessTokens accessTokens, Clock clock, AuthMetrics metrics) {
        this.transaction = Objects.requireNonNull(transaction);
        this.store = Objects.requireNonNull(store);
        this.secrets = Objects.requireNonNull(secrets);
        this.accessTokens = Objects.requireNonNull(accessTokens);
        this.clock = Objects.requireNonNull(clock);
        this.metrics = Objects.requireNonNull(metrics);
    }

    public Result refresh(String rawToken, Client client, UUID expectedSessionId) {
        Objects.requireNonNull(client);
        if (rawToken == null || rawToken.isBlank()) return Result.error(Status.INVALID);
        Result result = transaction.execute(() -> {
            LockedCredential credential = store.lockCredential(secrets.hash(rawToken), client);
            if (credential == null) return Result.error(Status.INVALID);
            ActiveSession session = credential.session();
            if (expectedSessionId != null && !expectedSessionId.equals(session.sessionId())) {
                return Result.error(Status.SESSION_CONTEXT_CHANGED);
            }
            if (!matchesClient(client, session)) return Result.error(Status.INVALID);
            Instant now = clock.instant();
            if (credential.usedAt() != null) {
                store.revoke(credential, now, "REFRESH_REUSED");
                return Result.error(Status.REFRESH_REUSED);
            }
            if (credential.revokedAt() != null || !now.isBefore(credential.tokenExpiresAt()) || !usable(session, now)) {
                return Result.error(Status.INVALID);
            }
            String next = secrets.newRefreshToken();
            store.rotate(credential, UUID.randomUUID(), secrets.hash(next), now);
            String access = accessTokens.sign(session, now, now.plus(ACCESS_LIFETIME));
            return new Result(Status.SUCCESS, access, next, session.sessionId(), ACCESS_LIFETIME.toSeconds());
        });
        if (result.status() == Status.REFRESH_REUSED)
            metrics.event(AuthMetrics.Event.REFRESH_REUSE, AuthMetrics.Outcome.REJECTED);
        return result;
    }

    /**
     * Logout deliberately accepts a previously rotated or expired credential and never rotates it.
     */
    public Status logout(String rawToken, Client client, UUID expectedSessionId) {
        Objects.requireNonNull(client);
        if (rawToken == null || rawToken.isBlank()) return Status.SUCCESS;
        return transaction.execute(() -> {
            LockedCredential credential = store.lockCredential(secrets.hash(rawToken), client);
            if (credential == null) return Status.SUCCESS;
            ActiveSession session = credential.session();
            if (expectedSessionId != null && !expectedSessionId.equals(session.sessionId()))
                return Status.SESSION_CONTEXT_CHANGED;
            if (!matchesClient(client, session)) return Status.INVALID;
            store.revoke(credential, clock.instant(), "LOGOUT");
            return Status.SUCCESS;
        });
    }

    /**
     * Verification of signature, algorithm, issuer and audience belongs to AccessTokens.
     */
    public boolean introspect(String token) {
        long start = System.nanoTime();
        boolean error = false;
        try {
            return introspectInternal(token);
        } catch (RuntimeException ex) {
            error = true;
            throw ex;
        } finally {
            metrics.introspection(System.nanoTime() - start, error);
        }
    }

    private boolean introspectInternal(String token) {
        VerifiedAccessToken verified = accessTokens.verify(token);
        if (verified == null) return false;
        Instant now = clock.instant();
        if (!now.isBefore(verified.expiresAt())) return false;
        ActiveSession session = store.findActive(verified.userId(), verified.sessionId());
        boolean active = session != null && verified.authVersion() == session.authVersion() && usable(session, now);
        if (active) store.markSeen(verified.userId(), verified.sessionId());
        return active;
    }

    private boolean matchesClient(Client client, ActiveSession session) {
        // The store must also validate the browser-context secret before returning WEB credentials.
        return client.clientId().equals(session.clientId()) && client.platform() == session.platform()
                && (client.platform() != Platform.WEB || client.browserContextHash() != null);
    }

    private boolean usable(ActiveSession session, Instant now) {
        return session.active() && session.userActive() && session.authVersion() == session.currentAuthVersion()
                && now.isBefore(session.expiresAt()) && now.isBefore(session.lastRefreshAt().plus(IDLE_LIFETIME));
    }

    public enum Status {SUCCESS, INVALID, SESSION_CONTEXT_CHANGED, REFRESH_REUSED}

    public record Result(Status status, String accessToken, String refreshToken, UUID sessionId, long expiresIn) {
        static Result error(Status status) {
            return new Result(status, null, null, null, 0);
        }
    }
}
