package com.d10g.ecommerce_auth.application.google;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Rules for resolving a verified Google identity; independent of storage and transport.
 */
public final class GoogleIdentityPolicy {
    private GoogleIdentityPolicy() {
    }

    /**
     * Previously issued Google challenges cannot cross an account-wide revocation.
     */
    public static boolean mayUseExistingIdentity(String status, Instant lastRevocation, Instant flowStartedAt) {
        return "ACTIVE".equals(status) && flowStartedAt != null
                && (lastRevocation == null || flowStartedAt.isAfter(lastRevocation));
    }

    /**
     * Linking additionally requires the account version captured by the challenge.
     */
    public static boolean mayLink(String status, long currentVersion, Long challengeVersion,
                                  Instant lastRevocation, Instant flowStartedAt) {
        return challengeVersion != null && challengeVersion == currentVersion
                && mayUseExistingIdentity(status, lastRevocation, flowStartedAt);
    }

    /**
     * Call with account state reread under the account lock and time sampled after that lock.
     */
    public static CollisionResult emailCollision(String status, Instant pendingUntil, Instant now) {
        Objects.requireNonNull(now);
        if (status == null) return new CollisionResult(Collision.AVAILABLE, 0);
        if ("PENDING_VERIFICATION".equals(status) && pendingUntil != null) {
            if (!now.isBefore(pendingUntil)) return new CollisionResult(Collision.RECLAIM_EXPIRED, 0);
            long millis = Duration.between(now, pendingUntil).toMillis();
            return new CollisionResult(Collision.REGISTRATION_PENDING, Math.max(1, (millis + 999) / 1000));
        }
        return new CollisionResult(Collision.ACCOUNT_LINK_REQUIRED, 0);
    }

    public enum Collision {AVAILABLE, RECLAIM_EXPIRED, REGISTRATION_PENDING, ACCOUNT_LINK_REQUIRED}

    public record CollisionResult(Collision outcome, long retryAfterSeconds) {
    }
}
