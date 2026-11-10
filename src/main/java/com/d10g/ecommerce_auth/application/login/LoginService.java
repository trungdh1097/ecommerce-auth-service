package com.d10g.ecommerce_auth.application.login;

import com.d10g.ecommerce_auth.application.login.LoginPorts.Challenge;
import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.login.LoginPorts.User;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.domain.account.Account;
import com.d10g.ecommerce_auth.application.observability.AuthMetrics;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Local password and OTP flow. An OTP failure is an outcome so attempts can commit.
 */
public final class LoginService {
    private static final Duration OTP_TTL = Duration.ofMinutes(5);
    private static final Duration RESEND_DELAY = Duration.ofSeconds(60);
    private static final int MAX_ATTEMPTS = 5;
    private final LoginPorts ports;
    private final AuthMetrics metrics;
    private final Duration trustedDeviceTtl;

    public LoginService(LoginPorts ports) {
        this(ports, AuthMetrics.NOOP);
    }

    public LoginService(LoginPorts ports, AuthMetrics metrics) {
        this(ports, metrics, Duration.ofDays(90));
    }

    public LoginService(LoginPorts ports, AuthMetrics metrics, Duration trustedDeviceTtl) {
        this.ports = Objects.requireNonNull(ports);
        this.metrics = Objects.requireNonNull(metrics);
        this.trustedDeviceTtl = Objects.requireNonNull(trustedDeviceTtl);
        if (trustedDeviceTtl.isNegative() || trustedDeviceTtl.isZero())
            throw new IllegalArgumentException("trusted device TTL must be positive");
    }

    private static String maskEmail(String email) {
        int at = email.indexOf('@');
        if (at <= 0) return "***";
        return email.substring(0, 1) + "***@" + email.substring(at + 1);
    }

    public Result login(String username, String password, Client client, String ip) {
        return login(username, password, client, ip, null, null);
    }

    public Result login(String username, String password, Client client, String ip, String deviceId, String deviceSecret) {
        return login(username, password, client, ip, deviceId, deviceSecret, false);
    }

    public Result login(String username, String password, Client client, String ip, String deviceId, String deviceSecret, boolean requireOtp) {
        try {
            Result result = loginInternal(username, password, client, ip, deviceId, deviceSecret, requireOtp);
            metrics.event(AuthMetrics.Event.LOGIN, result.status() == Status.ACCEPTED || result.status() == Status.SUCCESS ? AuthMetrics.Outcome.SUCCESS : AuthMetrics.Outcome.FAILURE);
            return result;
        } catch (RuntimeException ex) {
            metrics.event(AuthMetrics.Event.LOGIN, AuthMetrics.Outcome.ERROR);
            throw ex;
        }
    }

    private Result loginInternal(String username, String password, Client client, String ip, String deviceId, String deviceSecret, boolean requireOtp) {
        String normalized = Account.normalizeUsername(username);
        Objects.requireNonNull(client);
        ports.checkPasswordLimit(normalized, ip);
        User snapshot = ports.findUser(normalized);
        String hash = snapshot == null || snapshot.passwordHash() == null ? ports.dummyPasswordHash() : snapshot.passwordHash();
        boolean valid = ports.passwordMatches(password == null ? "" : password, hash);
        if (!valid || snapshot == null || snapshot.passwordHash() == null) {
            ports.recordPasswordFailure(normalized, ip);
            ports.inTransaction(() -> {
                ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.LOGIN_FAILURE, null,
                        com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome.FAILURE);
                return null;
            });
            return Result.status(Status.INVALID_CREDENTIALS);
        }
        ports.passwordSucceeded();
        return ports.inTransaction(() -> {
            User current = ports.lockUserForLogin(snapshot.id(), client);
            if (current == null || current.status() == Account.Status.DISABLED || current.authVersion() != snapshot.authVersion()
                    || !Objects.equals(current.passwordHash(), snapshot.passwordHash())) {
                ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.LOGIN_FAILURE,
                        current == null ? null : current.id(), com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome.FAILURE);
                return Result.status(Status.INVALID_CREDENTIALS);
            }
            if (!current.emailVerified() || current.status() != Account.Status.ACTIVE) {
                ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.LOGIN_FAILURE, current.id(),
                        com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome.FAILURE);
                return Result.status(!current.emailVerified() ? Status.EMAIL_VERIFICATION_REQUIRED : Status.INVALID_CREDENTIALS);
            }
            Instant now = ports.now();
            if (!requireOtp && ports.isTrusted(current, client, deviceId, deviceSecret, now)) {
                Tokens tokens = ports.completeTrusted(current, client, now);
                return new Result(Status.SUCCESS, null, null, null, null, null, tokens, null);
            }
            ports.checkMailLimit(current.id());
            UUID id = UUID.randomUUID();
            String binding = client.platform() == Platform.WEB ? null : ports.newNativeBinding();
            String otp = ports.newOtp();
            Instant expires = now.plus(OTP_TTL);
            byte[] mac = ports.otpMac(id, 1, otp);
            ports.createChallenge(id, current, client, binding, mac, now, expires, deviceId);
            ports.enqueueOtp(new Challenge(id, current, client.clientId(), current.authVersion(), mac, 1, 0, expires, now, false, false), otp, now);
            return new Result(Status.ACCEPTED, id, binding, expires, now.plus(RESEND_DELAY), maskEmail(current.email()), null, null);
        });
    }

    public Result verify(UUID challengeId, Client client, String binding, String otp) {
        try {
            Result result = verifyInternal(challengeId, client, binding, otp);
            metrics.event(AuthMetrics.Event.OTP, result.status() == Status.SUCCESS ? AuthMetrics.Outcome.SUCCESS : AuthMetrics.Outcome.FAILURE);
            return result;
        } catch (RuntimeException ex) {
            metrics.event(AuthMetrics.Event.OTP, AuthMetrics.Outcome.ERROR);
            throw ex;
        }
    }

    private Result verifyInternal(UUID challengeId, Client client, String binding, String otp) {
        Objects.requireNonNull(client);
        if (challengeId == null || otp == null || !otp.matches("[0-9]{6}")) return Result.status(Status.OTP_INVALID);
        return ports.inTransaction(() -> {
            Challenge challenge = ports.lockChallenge(challengeId, client, binding);
            Status error = validate(challenge);
            if (error != null) return Result.status(error);
            ports.checkOtpLimit(challenge.user().id(), challengeId);
            if (!ports.constantTimeEquals(challenge.otpMac(), ports.otpMac(challengeId, challenge.generation(), otp))) {
                ports.incrementAttempts(challenge);
                ports.recordOtpFailure(challenge.user().id(), challengeId);
                ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.LOGIN_FAILURE, challenge.user().id(),
                        com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome.FAILURE);
                if (challenge.attempts() + 1 >= MAX_ATTEMPTS)
                    ports.audit(com.d10g.ecommerce_auth.application.audit.AuditPort.EventType.OTP_BLOCKED, challenge.user().id(),
                            com.d10g.ecommerce_auth.application.audit.AuditPort.Outcome.FAILURE);
                return Result.status(Status.OTP_INVALID);
            }
            ports.otpSucceeded();
            Instant now = ports.now();
            Tokens tokens = ports.complete(challenge, client, now);
            String deviceSecret = ports.rememberDevice(challenge, client, now, now.plus(trustedDeviceTtl));
            return new Result(Status.SUCCESS, null, null, null, null, null, tokens, deviceSecret);
        });
    }

    public Result resend(UUID challengeId, Client client, String binding) {
        Objects.requireNonNull(client);
        if (challengeId == null) return Result.status(Status.CHALLENGE_INVALID);
        return ports.inTransaction(() -> {
            Challenge challenge = ports.lockChallenge(challengeId, client, binding);
            Status error = validate(challenge);
            if (error != null) return Result.status(error);
            Instant now = ports.now();
            if (now.isBefore(challenge.lastSentAt().plus(RESEND_DELAY))) return Result.status(Status.RESEND_TOO_SOON);
            ports.checkMailLimit(challenge.user().id());
            String otp = ports.newOtp();
            int generation = challenge.generation() + 1;
            Instant expires = now.plus(OTP_TTL);
            byte[] mac = ports.otpMac(challengeId, generation, otp);
            ports.resendOtp(challenge, mac, now, expires);
            ports.enqueueOtp(new Challenge(challenge.id(), challenge.user(), challenge.clientId(), challenge.authVersion(), mac,
                    generation, challenge.attempts(), expires, now, false, false), otp, now);
            return new Result(Status.ACCEPTED, challengeId, null, expires, now.plus(RESEND_DELAY), maskEmail(challenge.user().email()), null, null);
        });
    }

    private Status validate(Challenge challenge) {
        if (challenge == null || challenge.consumed() || challenge.superseded() || challenge.attempts() >= MAX_ATTEMPTS
                || challenge.user().status() != Account.Status.ACTIVE || !challenge.user().emailVerified()
                || challenge.authVersion() != challenge.user().authVersion()) return Status.CHALLENGE_INVALID;
        if (!ports.now().isBefore(challenge.expiresAt())) return Status.CHALLENGE_EXPIRED;
        return null;
    }

    public enum Status {ACCEPTED, SUCCESS, INVALID_CREDENTIALS, EMAIL_VERIFICATION_REQUIRED, CHALLENGE_INVALID, CHALLENGE_EXPIRED, OTP_INVALID, RESEND_TOO_SOON}

    public record Result(Status status, UUID challengeId, String nativeBinding, Instant expiresAt, Instant resendAt,
                         String maskedEmail, Tokens tokens, String deviceSecret) {
        static Result status(Status value) {
            return new Result(value, null, null, null, null, null, null, null);
        }
    }
}
