package com.d10g.ecommerce_auth.application.session;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class SessionServiceTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private final UUID user = UUID.randomUUID(), sessionId = UUID.randomUUID();
    private final Client client = new Client("android", Platform.ANDROID, null);
    private final ActiveSession session = new ActiveSession(user, sessionId, "android", Platform.ANDROID, 3,
            NOW.minusSeconds(30), "password otp", NOW.plusSeconds(3600), NOW.minusSeconds(60), true, true, 3);
    private final FakeStore store = new FakeStore();
    private final FakeTokens tokens = new FakeTokens();
    private final io.micrometer.core.instrument.simple.SimpleMeterRegistry registry = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
    private final SessionService service = new SessionService(new Transaction() {
        @Override public <T> T execute(Supplier<T> work) { return work.get(); }
    }, store, new Secrets() {
        @Override public String newRefreshToken() { return "new-secret"; }
        @Override public byte[] hash(String value) { return new byte[]{1}; }
    }, tokens, Clock.fixed(NOW, ZoneOffset.UTC), new com.d10g.ecommerce_auth.adapter.out.observability.MicrometerAuthMetrics(registry));

    private LockedCredential credential(Instant used) {
        return new LockedCredential(session, UUID.randomUUID(), UUID.randomUUID(), NOW.plusSeconds(600), used, null);
    }
    @Test void rotationReturnsNewCredentialAndUpdatesOnce() {
        store.credential = credential(null);
        var result = service.refresh("old", client, sessionId);
        assertEquals(SessionService.Status.SUCCESS, result.status());
        assertEquals("new-secret", result.refreshToken());
        assertTrue(store.rotated);
        assertNull(store.reason);
    }
    @Test void staleContextDoesNotRotateOrRevokeEvenIfTokenWasUsed() {
        store.credential = credential(NOW.minusSeconds(1));
        assertEquals(SessionService.Status.SESSION_CONTEXT_CHANGED, service.refresh("old", client, UUID.randomUUID()).status());
        assertFalse(store.rotated);
        assertNull(store.reason);
    }
    @Test void replayRevokesFamilyBeforeReturningFailure() {
        store.credential = credential(NOW.minusSeconds(1));
        assertEquals(SessionService.Status.REFRESH_REUSED, service.refresh("old", client, sessionId).status());
        assertEquals("REFRESH_REUSED", store.reason);
        assertEquals(1, registry.get("auth.events").tags("event", "refresh_reuse", "outcome", "rejected").counter().count());
    }
    @Test void logoutOfRotatedCredentialDoesNotReportReplay() {
        store.credential = credential(NOW.minusSeconds(1));
        assertEquals(SessionService.Status.SUCCESS, service.logout("old", client, sessionId));
        assertEquals("LOGOUT", store.reason);
    }
    @Test void introspectionRequiresCurrentUserVersionAndSession() {
        tokens.verified = new VerifiedAccessToken(user, sessionId, 2, NOW.plusSeconds(60));
        assertFalse(service.introspect("jwt"));
        tokens.verified = new VerifiedAccessToken(user, sessionId, 3, NOW.plusSeconds(60));
        assertTrue(service.introspect("jwt"));
        assertEquals(2, registry.get("auth.introspection").tag("outcome", "completed").timer().count());
    }
    @Test void introspectionRecordsDependencyErrorsWithoutHidingThem() {
        tokens.verified = new VerifiedAccessToken(user, sessionId, 3, NOW.plusSeconds(60));
        store.unavailable = true;
        assertThrows(IllegalStateException.class, () -> service.introspect("jwt"));
        assertEquals(1, registry.get("auth.introspection").tag("outcome", "error").timer().count());
    }
    private final class FakeStore implements Store {
        LockedCredential credential;
        boolean rotated;
        boolean unavailable;
        String reason;
        public LockedCredential lockCredential(byte[] hash, Client client) { return credential; }
        public void rotate(LockedCredential c, UUID id, byte[] hash, Instant time) { rotated = true; }
        public void revoke(LockedCredential c, Instant time, String value) { reason = value; }
        public ActiveSession findActive(UUID userId, UUID id) { if (unavailable) throw new IllegalStateException("db unavailable"); return session; }
    }
    private static final class FakeTokens implements AccessTokens {
        VerifiedAccessToken verified;
        public String sign(ActiveSession session, Instant now, Instant expires) { return "access"; }
        public VerifiedAccessToken verify(String token) { return verified; }
    }
}
