package com.d10g.ecommerce_auth.application.google;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class GoogleIdentityPolicyTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    @Test void previouslyStartedFlowsCannotOutliveRevocation() {
        assertTrue(GoogleIdentityPolicy.mayUseExistingIdentity("ACTIVE", NOW, NOW.plusNanos(1)));
        assertFalse(GoogleIdentityPolicy.mayUseExistingIdentity("ACTIVE", NOW, NOW));
        assertFalse(GoogleIdentityPolicy.mayUseExistingIdentity("DISABLED", null, NOW));
        assertFalse(GoogleIdentityPolicy.mayLink("ACTIVE", 2, 1L, null, NOW));
        assertTrue(GoogleIdentityPolicy.mayLink("ACTIVE", 2, 2L, null, NOW));
    }

    @Test void pendingRegistrationExpiresAtTheExactDeadline() {
        var pending = GoogleIdentityPolicy.emailCollision("PENDING_VERIFICATION", NOW.plusMillis(1001), NOW);
        assertEquals(GoogleIdentityPolicy.Collision.REGISTRATION_PENDING, pending.outcome());
        assertEquals(2, pending.retryAfterSeconds());
        assertEquals(GoogleIdentityPolicy.Collision.RECLAIM_EXPIRED,
                GoogleIdentityPolicy.emailCollision("PENDING_VERIFICATION", NOW, NOW).outcome());
        assertEquals(GoogleIdentityPolicy.Collision.ACCOUNT_LINK_REQUIRED,
                GoogleIdentityPolicy.emailCollision("ACTIVE", null, NOW).outcome());
        assertEquals(GoogleIdentityPolicy.Collision.AVAILABLE,
                GoogleIdentityPolicy.emailCollision(null, null, NOW).outcome());
    }
}
