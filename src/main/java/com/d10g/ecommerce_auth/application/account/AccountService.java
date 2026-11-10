package com.d10g.ecommerce_auth.application.account;

import com.d10g.ecommerce_auth.domain.account.Account;
import com.d10g.ecommerce_auth.application.account.AccountPorts.Challenge;
import com.d10g.ecommerce_auth.application.account.AccountPorts.Purpose;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Use cases for registration and email-based account recovery.
 */
public final class AccountService {
    private static final Duration REGISTRATION_TTL = Duration.ofHours(24);
    private static final Duration VERIFICATION_TTL = Duration.ofHours(24);
    private static final Duration RESET_TTL = Duration.ofMinutes(15);
    private final AccountPorts ports;

    public AccountService(AccountPorts ports) {
        this.ports = ports;
    }

    public Result register(String rawUsername, String rawEmail, String password) {
        String username = Account.normalizeUsername(rawUsername);
        String email = Account.normalizeEmail(rawEmail);
        Account.validatePassword(password);
        String hash = ports.hashPassword(password);
        try {
            return ports.inTransaction(() -> {
                ports.lockRegistration(username, email);
                Instant now = ports.databaseTime();
                Optional<Account> byUsername = ports.lockByUsername(username);
                if (byUsername.isPresent() && byUsername.get().pendingExpired(now)) {
                    ports.deleteExpiredPending(byUsername.get());
                    byUsername = Optional.empty();
                }
                Optional<Account> byEmail = ports.lockByEmail(email);
                if (byEmail.isPresent() && byEmail.get().pendingExpired(now)) {
                    ports.deleteExpiredPending(byEmail.get());
                    byEmail = Optional.empty();
                }
                // An existing email must not be disclosed, including when the username also matches it.
                if (byEmail.isPresent()) return Result.ACCEPTED;
                if (byUsername.isPresent()) return Result.USERNAME_UNAVAILABLE;
                UUID id = UUID.randomUUID();
                Instant expiry = now.plus(REGISTRATION_TTL);
                ports.insertPending(id, username, email, hash, now, expiry);
                configRole(id);
                issue(id, email, Purpose.VERIFY_EMAIL, 0, now, expiry);
                return Result.ACCEPTED;
            });
        } catch (AccountPorts.RegistrationConflict conflict) {
            // A competing writer (including Google signup) won a uniqueness race.
            return ports.inTransaction(() -> {
                ports.lockRegistration(username, email);
                if (ports.lockByEmail(email).isPresent()) return Result.ACCEPTED;
                return ports.lockByUsername(username).isPresent() ? Result.USERNAME_UNAVAILABLE : Result.ACCEPTED;
            });
        }
    }

    public Result resendVerification(String rawEmail) {
        String email = Account.normalizeEmail(rawEmail);
        return ports.inTransaction(() -> {
            Optional<Account> account = ports.lockByEmail(email);
            Instant now = ports.databaseTime();
            account.filter(a -> !a.emailVerified() && a.mayVerify(now)).ifPresent(a -> {
                Instant expires = now.plus(VERIFICATION_TTL);
                if (a.status() == Account.Status.PENDING_VERIFICATION && a.registrationExpiresAt().isBefore(expires))
                    expires = a.registrationExpiresAt();
                ports.supersedeChallenges(a.id(), Purpose.VERIFY_EMAIL, now);
                issue(a.id(), a.email(), Purpose.VERIFY_EMAIL, a.authVersion(), now, expires);
            });
            return Result.ACCEPTED;
        });
    }

    public Result verifyEmail(String token) {
        return consume(token, Purpose.VERIFY_EMAIL, null);
    }

    public Result forgotPassword(String rawEmail) {
        String email = Account.normalizeEmail(rawEmail);
        return ports.inTransaction(() -> {
            Optional<Account> account = ports.lockByEmail(email);
            Instant now = ports.databaseTime();
            account.filter(Account::mayResetPassword).ifPresent(a -> {
                ports.supersedeChallenges(a.id(), Purpose.RESET_PASSWORD, now);
                issue(a.id(), a.email(), Purpose.RESET_PASSWORD, a.authVersion(), now, now.plus(RESET_TTL));
            });
            return Result.ACCEPTED;
        });
    }

    public Result resetPassword(String token, String password) {
        Account.validatePassword(password);
        return consume(token, Purpose.RESET_PASSWORD, ports.hashPassword(password));
    }

    private Result consume(String token, Purpose purpose, String newPasswordHash) {
        if (token == null || token.isBlank()) return Result.INVALID_TOKEN;
        return ports.inTransaction(() -> {
            Optional<Challenge> candidate = ports.findChallenge(ports.hashToken(token), purpose);
            if (candidate.isEmpty()) return Result.INVALID_TOKEN;
            Optional<Account> account = ports.lockById(candidate.get().userId());
            Optional<Challenge> locked = ports.lockChallenge(candidate.get().id());
            if (account.isEmpty() || locked.isEmpty()) return Result.INVALID_TOKEN;
            Account a = account.get();
            Challenge c = locked.get();
            Instant now = ports.databaseTime();
            if (c.consumed() || c.superseded() || !now.isBefore(c.expiresAt()) || !a.mayVerify(now)
                    || (purpose == Purpose.RESET_PASSWORD && (c.authVersion() != a.authVersion() || !a.mayResetPassword())))
                return Result.INVALID_TOKEN;
            ports.consumeChallenge(c.id(), now);
            if (purpose == Purpose.VERIFY_EMAIL) ports.markEmailVerified(a.id(), now);
            else {
                ports.changePasswordAndRevoke(a.id(), newPasswordHash);
                ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.PASSWORD_RESET, a.id());
            }
            return Result.OK;
        });
    }

    public Result changePassword(UUID userId, UUID sessionId, String currentPassword, String newPassword) {
        Account.validatePassword(newPassword);
        String newHash = ports.hashPassword(newPassword);
        return ports.inTransaction(() -> {
            Optional<Account> user = ports.lockById(userId);
            if (user.isEmpty() || !user.get().mayResetPassword()) return Result.INVALID_CREDENTIALS;
            Optional<AccountPorts.SessionAuthentication> session = ports.lockAuthenticatedSession(userId, sessionId, user.get().authVersion());
            Instant now = ports.databaseTime();
            if (session.isEmpty()) return Result.INVALID_CREDENTIALS;
            var authenticated = session.get();
            if (!now.isBefore(authenticated.expiresAt()) || !now.isBefore(authenticated.lastRefreshAt().plus(Duration.ofDays(7))) ||
                    authenticated.authTime().isAfter(now) || authenticated.authTime().isBefore(now.minus(Duration.ofMinutes(5))) ||
                    "pwd".equals(authenticated.authenticationMethod()))
                return Result.REAUTHENTICATION_REQUIRED;
            if (!ports.passwordMatches(currentPassword, user.get().passwordHash())) return Result.INVALID_CREDENTIALS;
            ports.changePasswordAndRevoke(userId, newHash);
            ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.PASSWORD_CHANGE, userId);
            return Result.OK;
        });
    }

    private void issue(UUID userId, String email, Purpose purpose, long version, Instant now, Instant expiry) {
        String token = ports.newToken();
        UUID id = UUID.randomUUID();
        ports.insertChallenge(id, userId, purpose, ports.hashToken(token), version, now, expiry);
        ports.enqueueEmail(id, userId, email, purpose, token, expiry);
    }

    private void configRole(UUID userId){
        ports.insertUserRole(userId);
    }

    public enum Result {ACCEPTED, OK, USERNAME_UNAVAILABLE, INVALID_TOKEN, INVALID_CREDENTIALS, REAUTHENTICATION_REQUIRED}
}
