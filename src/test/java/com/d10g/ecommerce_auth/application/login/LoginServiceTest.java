package com.d10g.ecommerce_auth.application.login;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.domain.account.Account;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class LoginServiceTest {
    private final Fake ports = new Fake();
    private final io.micrometer.core.instrument.simple.SimpleMeterRegistry registry = new io.micrometer.core.instrument.simple.SimpleMeterRegistry();
    private final LoginService service = new LoginService(ports, new com.d10g.ecommerce_auth.adapter.out.observability.MicrometerAuthMetrics(registry));
    private final Client client = new Client("android", Platform.ANDROID, null);
    @Test void unknownUserUsesDummyAndDoesNotIssueChallenge() {
        ports.snapshot = null;
        assertEquals(LoginService.Status.INVALID_CREDENTIALS, service.login("alice", "bad", client, "ip").status());
        assertEquals("dummy", ports.checkedHash);
        assertFalse(ports.created);
        assertEquals(1, registry.get("auth.events").tags("event", "login", "outcome", "failure").counter().count());
    }
    @Test void passwordSnapshotCannotBeReusedAfterReset() {
        ports.current = new LoginPorts.User(ports.snapshot.id(), "alice", "a@example.com", "new-hash", 2, Account.Status.ACTIVE, true);
        assertEquals(LoginService.Status.INVALID_CREDENTIALS, service.login("alice", "correct", client, "ip").status());
        assertFalse(ports.created);
    }
    @Test void successfulPasswordOnlyCreatesChallengeNotSession() {
        var result = service.login("alice", "correct", client, "ip");
        assertEquals(LoginService.Status.ACCEPTED, result.status());
        assertNotNull(result.challengeId()); assertEquals("binding", result.nativeBinding());
        assertTrue(ports.created); assertFalse(ports.completed);
    }
    @Test void trustedDeviceStillRequiresCorrectPasswordAndBypassesOtpOnlyAfterAccountChecks() {
        ports.trusted = true;
        assertEquals(LoginService.Status.INVALID_CREDENTIALS, service.login("alice", "bad", client, "ip", "device", "secret").status());
        assertFalse(ports.trustChecked);
        var result = service.login("alice", "correct", client, "ip", "device", "secret");
        assertEquals(LoginService.Status.SUCCESS, result.status());
        assertTrue(ports.trustedCompleted);
        assertFalse(ports.created);
        assertEquals("device", ports.checkedDeviceId);
        assertEquals("secret", ports.checkedDeviceSecret);
        assertEquals(1, registry.get("auth.events").tags("event", "login", "outcome", "success").counter().count());
    }
    @Test void untrustedDeviceIsBoundToChallengeAndRememberedOnlyAfterOtpSuccess() {
        var login = service.login("alice", "correct", client, "ip", "device", "incorrect-secret");
        assertEquals(LoginService.Status.ACCEPTED, login.status());
        assertEquals("device", ports.challengeDeviceId);
        ports.challenge = ports.challenge(0);
        assertEquals(LoginService.Status.OTP_INVALID, service.verify(ports.challenge.id(), client, "binding", "999999").status());
        assertFalse(ports.remembered);
        var verified = service.verify(ports.challenge.id(), client, "binding", "123456");
        assertEquals("new-secret", verified.deviceSecret());
        assertTrue(ports.remembered);
        assertEquals(ports.now.plusSeconds(90L * 24 * 60 * 60), ports.trustExpiresAt);
    }
    @Test void trustedDeviceCanRequestFreshOtpForSensitiveActions() {
        ports.trusted = true;
        var result = service.login("alice", "correct", client, "ip", "device", "secret", true);
        assertEquals(LoginService.Status.ACCEPTED, result.status());
        assertTrue(ports.created);
        assertFalse(ports.trustChecked);
        assertFalse(ports.trustedCompleted);
    }
    @Test void trustedDeviceCannotBypassAccountStatusChecks() {
        ports.trusted = true;
        ports.current = new LoginPorts.User(ports.snapshot.id(), "alice", "a@example.com", "hash", 1, Account.Status.ACTIVE, false);
        assertEquals(LoginService.Status.EMAIL_VERIFICATION_REQUIRED,
                service.login("alice", "correct", client, "ip", "device", "secret").status());
        assertFalse(ports.trustChecked);
        assertFalse(ports.trustedCompleted);
    }
    @Test void trustLifetimeUsesConfiguredDuration() {
        LoginService configured = new LoginService(ports, com.d10g.ecommerce_auth.application.observability.AuthMetrics.NOOP, java.time.Duration.ofDays(12));
        ports.challenge = ports.challenge(0);
        assertEquals(LoginService.Status.SUCCESS, configured.verify(ports.challenge.id(), client, "binding", "123456").status());
        assertEquals(ports.now.plusSeconds(12L * 24 * 60 * 60), ports.trustExpiresAt);
    }
    @Test void wrongOtpIsRecordedWithoutCompletingAndCorrectOtpCompletes() {
        ports.challenge = ports.challenge(0);
        assertEquals(LoginService.Status.OTP_INVALID, service.verify(ports.challenge.id(), client, "binding", "999999").status());
        assertEquals(1, ports.failures); assertFalse(ports.completed);
        assertEquals(LoginService.Status.SUCCESS, service.verify(ports.challenge.id(), client, "binding", "123456").status());
        assertTrue(ports.completed);
        assertEquals(1, registry.get("auth.events").tags("event", "otp", "outcome", "failure").counter().count());
        assertEquals(1, registry.get("auth.events").tags("event", "otp", "outcome", "success").counter().count());
        assertFalse(registry.getMeters().stream().anyMatch(m -> m.getId().getTags().stream().anyMatch(t -> t.getValue().contains("alice"))));
    }
    @Test void resendMaintainsAttemptsAndChangesGeneration() {
        ports.challenge = ports.challenge(3);
        var result = service.resend(ports.challenge.id(), client, "binding");
        assertEquals(LoginService.Status.ACCEPTED, result.status());
        assertEquals(3, ports.enqueued.attempts()); assertEquals(2, ports.enqueued.generation());
    }
    @Test void fifthOtpFailureRecordsBlockedAudit() {
        ports.challenge = ports.challenge(4);
        assertEquals(LoginService.Status.OTP_INVALID, service.verify(ports.challenge.id(), client, "binding", "999999").status());
        assertTrue(ports.auditEvents.contains(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.OTP_BLOCKED));
        assertTrue(ports.auditEvents.contains(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.LOGIN_FAILURE));
        assertFalse(ports.completed);
    }
    private static final class Fake implements LoginPorts {
        final Instant now = Instant.parse("2026-01-01T00:00:00Z");
        User snapshot = new User(UUID.randomUUID(), "alice", "a@example.com", "hash", 1, Account.Status.ACTIVE, true);
        User current = snapshot;
        Challenge challenge, enqueued;
        String checkedHash, checkedDeviceId, checkedDeviceSecret, challengeDeviceId;
        boolean created, completed, trusted, trustChecked, trustedCompleted, remembered; int failures;
        Instant trustExpiresAt;
        final java.util.List<com.d10g.ecommerce_auth.application.audit.AuditPort.EventType> auditEvents = new java.util.ArrayList<>();
        public void audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType event, UUID userId,
                          com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome outcome) { auditEvents.add(event); }
        public <T> T inTransaction(Supplier<T> work) { return work.get(); }
        public User findUser(String name) { return snapshot; }
        public User lockUserForLogin(UUID id, Client client) { return current; }
        public Challenge lockChallenge(UUID id, Client client, String binding) { return "binding".equals(binding) ? challenge : null; }
        public Instant now() { return now; }
        public boolean passwordMatches(String password, String hash) { checkedHash=hash; return "correct".equals(password); }
        public String dummyPasswordHash() { return "dummy"; }
        public String newNativeBinding() { return "binding"; }
        public String newOtp() { return "123456"; }
        public byte[] otpMac(UUID id, int generation, String otp) { return (id + ":" + generation + ":" + otp).getBytes(StandardCharsets.UTF_8); }
        public boolean constantTimeEquals(byte[] a, byte[] b) { return Arrays.equals(a,b); }
        public void createChallenge(UUID id, User user, Client client, String binding, byte[] mac, Instant now, Instant expiry, String deviceId) { created = true; challengeDeviceId = deviceId; }
        public boolean isTrusted(User user, Client client, String deviceId, String secret, Instant now) { trustChecked = true; checkedDeviceId = deviceId; checkedDeviceSecret = secret; return trusted; }
        public Tokens completeTrusted(User user, Client client, Instant now) { trustedCompleted = true; return new Tokens("access", "refresh", UUID.randomUUID(), 300); }
        public String rememberDevice(Challenge challenge, Client client, Instant now, Instant expiresAt) { assertTrue(completed); remembered = true; trustExpiresAt = expiresAt; return "new-secret"; }
        public void enqueueOtp(Challenge c, String otp, Instant now) { enqueued = c; }
        public void incrementAttempts(Challenge c) { failures++; }
        public void resendOtp(Challenge c, byte[] mac, Instant now, Instant expiry) { }
        public Tokens complete(Challenge c, Client client, Instant now) { completed = true; return new Tokens("access", "refresh", UUID.randomUUID(), 300); }
        public void checkPasswordLimit(String username, String ip) { }
        public void recordPasswordFailure(String username, String ip) { }
        public void checkOtpLimit(UUID user, UUID challenge) { }
        public void recordOtpFailure(UUID user, UUID challenge) { }
        public void checkMailLimit(UUID user) { }
        Challenge challenge(int attempts) {
            UUID id=UUID.randomUUID();
            return new Challenge(id, current, "android", 1, otpMac(id, 1, "123456"), 1, attempts, now.plusSeconds(60), now.minusSeconds(61), false, false);
        }
    }
}
