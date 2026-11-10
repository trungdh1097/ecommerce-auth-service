package com.d10g.ecommerce_auth.application.account;

import com.d10g.ecommerce_auth.domain.account.Account;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AccountServiceTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private final Fake ports = new Fake();
    private final AccountService service = new AccountService(ports);
    private final UUID userId = UUID.randomUUID();
    private final UUID challengeId = UUID.randomUUID();

    @Test void resendNeverExtendsPendingRegistration() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", false,
                Account.Status.PENDING_VERIFICATION, NOW.plusSeconds(60), 0);
        assertEquals(AccountService.Result.ACCEPTED, service.resendVerification(" A@example.com "));
        assertEquals(NOW.plusSeconds(60), ports.issuedExpiry);
        assertTrue(ports.emailQueued);
    }
    @Test void disabledUserCannotBeActivatedWithVerificationLink() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", false, Account.Status.DISABLED, null, 0);
        ports.challenge = new AccountPorts.Challenge(challengeId, userId, AccountPorts.Purpose.VERIFY_EMAIL, 0, NOW.plusSeconds(60), false, false);
        assertEquals(AccountService.Result.INVALID_TOKEN, service.verifyEmail("secret"));
        assertFalse(ports.verified || ports.consumed);
    }
    @Test void resetRejectsChallengeFromBeforeLogoutAll() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true, Account.Status.ACTIVE, null, 4);
        ports.challenge = new AccountPorts.Challenge(challengeId, userId, AccountPorts.Purpose.RESET_PASSWORD, 3, NOW.plusSeconds(60), false, false);
        assertEquals(AccountService.Result.INVALID_TOKEN, service.resetPassword("secret", "long enough password"));
        assertFalse(ports.revoked);
    }
    @Test void forgotGoogleOnlyAccountDoesNotIssueReset() {
        ports.account = new Account(userId, null, "a@example.com", null, true, Account.Status.ACTIVE, null, 0);
        assertEquals(AccountService.Result.ACCEPTED, service.forgotPassword("a@example.com"));
        assertNull(ports.issuedExpiry);
    }
    @Test void registrationConflictDoesNotDiscloseExistingEmail() {
        ports.failFirstTransaction = true;
        ports.account = new Account(userId, "other", "a@example.com", "hash", true, Account.Status.ACTIVE, null, 0);
        assertEquals(AccountService.Result.ACCEPTED, service.register("name", "a@example.com", "long enough password"));
        assertTrue(ports.registrationLocked);
    }
    @Test void resendChecksExpiryAfterWaitingForAccountLock() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", false,
                Account.Status.PENDING_VERIFICATION, NOW.plusSeconds(1), 0);
        ports.advanceOnLock = true;
        assertEquals(AccountService.Result.ACCEPTED, service.resendVerification("a@example.com"));
        assertFalse(ports.emailQueued);
        assertNull(ports.issuedExpiry);
    }
    @Test void passwordChangeChecksAuthenticationTimeAfterWaitingForLock() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true,
                Account.Status.ACTIVE, null, 0);
        ports.advanceOnLock = true;
        assertEquals(AccountService.Result.REAUTHENTICATION_REQUIRED,
                service.changePassword(userId, UUID.randomUUID(), "old password", "long enough password"));
        assertFalse(ports.revoked);
    }
    @Test void resetLinkLifetimeStartsAfterAccountLock() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true,
                Account.Status.ACTIVE, null, 0);
        ports.advanceOnLock = true;
        assertEquals(AccountService.Result.ACCEPTED, service.forgotPassword("a@example.com"));
        assertEquals(NOW.plusSeconds(2 + 15 * 60), ports.issuedExpiry);
    }
    @Test void passwordChangeRejectsSessionRevokedBeforeUserLock() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true,
                Account.Status.ACTIVE, null, 0);
        ports.sessionRevoked = true;
        assertEquals(AccountService.Result.INVALID_CREDENTIALS,
                service.changePassword(userId, UUID.randomUUID(), "old password", "long enough password"));
        assertFalse(ports.revoked);
    }
    @Test void passwordChangeSucceedsForRecentLiveSession() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true,
                Account.Status.ACTIVE, null, 0);
        ports.passwordValid = true;
        assertEquals(AccountService.Result.OK,
                service.changePassword(userId, UUID.randomUUID(), "old password", "long enough password"));
        assertTrue(ports.revoked);
    }
    @Test void passwordOnlyTrustedLoginRequiresOtpForPasswordChange() {
        ports.account = new Account(userId, "name", "a@example.com", "hash", true,
                Account.Status.ACTIVE, null, 0);
        ports.authenticationMethod = "pwd";
        ports.passwordValid = true;
        assertEquals(AccountService.Result.REAUTHENTICATION_REQUIRED,
                service.changePassword(userId, UUID.randomUUID(), "old password", "long enough password"));
        assertFalse(ports.revoked);
    }
    private static final class Fake implements AccountPorts {
        Account account;
        Challenge challenge;
        Instant issuedExpiry;
        boolean verified, consumed, revoked, emailQueued, failFirstTransaction, registrationLocked, advanceOnLock, sessionRevoked, passwordValid;
        Instant currentTime = NOW;
        String authenticationMethod = "pwd otp";
        public <T> T inTransaction(Supplier<T> task) {
            if (failFirstTransaction) { failFirstTransaction = false; throw new RegistrationConflict(new RuntimeException()); }
            return task.get();
        }
        public void lockRegistration(String username, String email) { registrationLocked = true; }
        public Instant databaseTime() { return currentTime; }
        public Optional<Account> lockById(UUID id) { advance(); return Optional.ofNullable(account); }
        public Optional<SessionAuthentication> lockAuthenticatedSession(UUID user, UUID session, long version) {
            if (sessionRevoked) return Optional.empty();
            return Optional.of(new SessionAuthentication(NOW.minusSeconds(299), NOW.plusSeconds(3600), NOW, authenticationMethod));
        }
        public Optional<Account> lockByUsername(String username) { return Optional.ofNullable(account).filter(a -> username.equals(a.username())); }
        public Optional<Account> lockByEmail(String email) { advance(); return Optional.ofNullable(account).filter(a -> email.equals(a.email())); }
        private void advance() { if (advanceOnLock) currentTime = currentTime.plusSeconds(2); }
        public void deleteExpiredPending(Account value) { account = null; }
        public void insertPending(UUID id, String username, String email, String hash, Instant now, Instant expiry) { }
        public Optional<Challenge> findChallenge(String hash, Purpose purpose) { return Optional.ofNullable(challenge); }
        public Optional<Challenge> lockChallenge(UUID id) { return Optional.ofNullable(challenge); }
        public void supersedeChallenges(UUID user, Purpose purpose, Instant now) { }
        public void insertChallenge(UUID id, UUID user, Purpose purpose, String hash, long version, Instant now, Instant expiry) { issuedExpiry = expiry; }
        public void consumeChallenge(UUID id, Instant now) { consumed = true; }
        public void markEmailVerified(UUID id, Instant now) { verified = true; }
        public void changePasswordAndRevoke(UUID id, String hash) { revoked = true; }
        public void enqueueEmail(UUID id, UUID user, String email, Purpose purpose, String token, Instant expiry) { emailQueued = true; }
        public String hashPassword(String password) { return "hash"; }
        public boolean passwordMatches(String password, String hash) { return passwordValid; }
        public String newToken() { return "secret"; }
        public String hashToken(String token) { return "hash"; }
        public void insertUserRole(UUID id) { }
    }
}
