package com.d10g.ecommerce_auth.adapter.out.login;

import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionIssuer;
import com.d10g.ecommerce_auth.application.login.LoginPorts;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.domain.account.Account;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.d10g.ecommerce_auth.security.crypto.OutboxCipher;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * PostgreSQL login flow; transaction boundaries are owned by the application service.
 */
public final class JdbcLoginAdapter implements LoginPorts {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;
    private final LoginCrypto crypto;
    private final OpaqueSecrets secrets;
    private final OutboxCipher outboxCipher;
    private final String keyId;
    private final JdbcSessionIssuer issuer;
    private final LoginRateLimits limits;
    private final AuditPort audit;

    public JdbcLoginAdapter(JdbcTemplate db, TransactionTemplate transaction, LoginCrypto crypto,
                            OpaqueSecrets secrets, OutboxCipher outboxCipher, String keyId,
                            JdbcSessionIssuer issuer, LoginRateLimits limits) {
        this.db = Objects.requireNonNull(db);
        this.transaction = Objects.requireNonNull(transaction);
        this.crypto = Objects.requireNonNull(crypto);
        this.secrets = Objects.requireNonNull(secrets);
        this.outboxCipher = Objects.requireNonNull(outboxCipher);
        this.keyId = Objects.requireNonNull(keyId);
        this.issuer = Objects.requireNonNull(issuer);
        this.limits = Objects.requireNonNull(limits);
        this.audit = new JdbcAuditRecorder(db, secrets);
    }

    private static User user(ResultSet rs) throws SQLException {
        return new User(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("email"), rs.getString("password_hash"), rs.getLong("auth_version"), Account.Status.valueOf(rs.getString("status")), rs.getBoolean("email_verified"));
    }

    private static Instant time(ResultSet rs, String col) throws SQLException {
        Timestamp t = rs.getTimestamp(col);
        return t == null ? null : t.toInstant();
    }

    private static Timestamp ts(Instant value) {
        return Timestamp.from(value);
    }

    private static <T> T one(List<T> rows) {
        return rows.isEmpty() ? null : rows.get(0);
    }

    @Override
    public void audit(AuditPort.EventType event, UUID userId, AuditPort.Outcome outcome) {
        audit.record(event, userId, null, outcome, null);
    }

    @Override
    public <T> T inTransaction(Supplier<T> work) {
        return transaction.execute(status -> work.get());
    }

    @Override
    public User findUser(String username) {
        return one(db.query("select * from users where username=?", (rs, n) -> user(rs), username));
    }

    @Override
    public User lockUserForLogin(UUID userId, Client client) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        if (client.platform() == Platform.WEB && context == null) return null;
        if (client.platform() != Platform.WEB && client.browserContextHash() != null) return null;
        UUID current = context == null ? null : one(db.query("select user_id from sessions where browser_context_id=? and platform='WEB' and status='ACTIVE'", (rs, n) -> rs.getObject(1, UUID.class), context));
        if (current == null || current.equals(userId)) {
            db.query("select id from users where id=? order by id for update", rs -> {}, userId);
        } else {
            db.query("select id from users where id in (?,?) order by id for update", rs -> {}, userId, current);
        }
        return one(db.query("select * from users where id=? for update", (rs, n) -> user(rs), userId));
    }

    @Override
    public Challenge lockChallenge(UUID challengeId, Client client, String nativeBinding) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        if (client.platform() == Platform.WEB && context == null) return null;
        if (client.platform() != Platform.WEB && (client.browserContextHash() != null || nativeBinding == null || nativeBinding.isBlank()))
            return null;
        UUID target = one(db.query("select user_id from auth_challenges where id=? and purpose='LOGIN_OTP'", (rs, n) -> rs.getObject(1, UUID.class), challengeId));
        if (target == null) return null;
        UUID current = context == null ? null : one(db.query("select user_id from sessions where browser_context_id=? and platform='WEB' and status='ACTIVE'", (rs, n) -> rs.getObject(1, UUID.class), context));
        if (current == null || current.equals(target)) {
            db.query("select id from users where id=? order by id for update", rs -> {
            }, target);
        } else {
            db.query("select id from users where id in (?,?) order by id for update", rs -> {
            }, target, current);
        }
        return one(db.query("select c.*,u.username,u.email,u.password_hash,u.status,u.email_verified,u.auth_version current_version from auth_challenges c join users u on u.id=c.user_id where c.id=? and c.user_id=? and c.purpose='LOGIN_OTP' for update of c", (rs, n) -> {
            if (!client.clientId().equals(rs.getString("client_id"))) return null;
            String challengePlatform = rs.getString("device_platform");
            if (challengePlatform != null && !client.platform().name().equals(challengePlatform)) return null;
            UUID actualContext = rs.getObject("browser_context_id", UUID.class);
            if (client.platform() == Platform.WEB) {
                if (!Objects.equals(context, actualContext)) return null;
            } else {
                byte[] expected = rs.getBytes("binding_hash");
                if (actualContext != null || !crypto.constantTimeEquals(expected, crypto.hashBinding(nativeBinding)))
                    return null;
            }
            User user = new User(target, rs.getString("username"), rs.getString("email"), rs.getString("password_hash"),
                    rs.getLong("current_version"), Account.Status.valueOf(rs.getString("status")), rs.getBoolean("email_verified"));
            return new Challenge(challengeId, user, rs.getString("client_id"), rs.getLong("auth_version"), rs.getBytes("otp_mac"),
                    rs.getInt("generation"), rs.getInt("attempts"), time(rs, "expires_at"), time(rs, "last_sent_at"),
                    rs.getTimestamp("consumed_at") != null, rs.getTimestamp("superseded_at") != null);
        }, challengeId, target));
    }

    private UUID lockContext(Client client) {
        byte[] hash = client.browserContextHash();
        if (hash == null) return null;
        return one(db.query("select id from browser_contexts where secret_hash=? for update", (rs, n) -> rs.getObject(1, UUID.class), hash));
    }

    @Override
    public Instant now() {
        return Objects.requireNonNull(db.queryForObject("select clock_timestamp()", Timestamp.class)).toInstant();
    }

    @Override
    public boolean passwordMatches(String password, String hash) {
        return crypto.passwordMatches(password, hash);
    }

    @Override
    public String dummyPasswordHash() {
        return crypto.dummyPasswordHash();
    }

    @Override
    public String newNativeBinding() {
        return crypto.newNativeBinding();
    }

    @Override
    public String newOtp() {
        return crypto.newOtp();
    }

    @Override
    public byte[] otpMac(UUID id, int generation, String otp) {
        return crypto.otpMac(id, generation, otp);
    }

    @Override
    public boolean constantTimeEquals(byte[] first, byte[] second) {
        return crypto.constantTimeEquals(first, second);
    }

    @Override
    public void createChallenge(UUID id, User user, Client client, String nativeBinding, byte[] mac, Instant now, Instant expires, String deviceId) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        if (client.platform() == Platform.WEB && context == null)
            throw new IllegalStateException("Browser context is missing");
        byte[] binding = client.platform() == Platform.WEB ? null : crypto.hashBinding(Objects.requireNonNull(nativeBinding));
        var metadata = client.metadata();
        db.update("insert into auth_challenges(id,purpose,user_id,browser_context_id,binding_hash,client_id,auth_version,otp_mac,generation,attempts,expires_at,last_sent_at,created_at,device_label,user_agent,masked_ip,device_id,device_platform) values (?,'LOGIN_OTP',?,?,?,?,?,?,1,0,?,?,?,?,?,?,?,?)",
                id, user.id(), context, binding, client.clientId(), user.authVersion(), mac, ts(expires), ts(now), ts(now),
                metadata == null ? null : metadata.deviceLabel(), metadata == null ? null : metadata.userAgent(), metadata == null ? null : metadata.maskedIp(),
                client.platform() == Platform.WEB ? null : deviceId, client.platform().name());
    }

    @Override
    public boolean isTrusted(User user, Client client, String deviceId, String deviceSecret, Instant now) {
        if (client.platform() == Platform.WEB) {
            UUID context = lockContext(client);
            if (context == null) return false;
            return !db.query("select id from trusted_devices where user_id=? and client_id=? and platform='WEB' and browser_context_id=? and auth_version=? and expires_at>?",
                    (rs, n) -> rs.getObject(1, UUID.class), user.id(), client.clientId(), context, user.authVersion(), ts(now)).isEmpty();
        }
        if (deviceId == null || deviceId.isBlank() || deviceSecret == null || deviceSecret.isBlank()) return false;
        byte[] expected = one(db.query("select secret_hash from trusted_devices where user_id=? and client_id=? and platform=? and device_id=? and auth_version=? and expires_at>?",
                (rs, n) -> rs.getBytes(1), user.id(), client.clientId(), client.platform().name(), deviceId, user.authVersion(), ts(now)));
        return crypto.constantTimeEquals(expected, crypto.hashBinding(deviceSecret));
    }

    @Override
    public Tokens completeTrusted(User user, Client client, Instant now) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        return issuer.issue(user.id(), user.authVersion(), client, context, now, "pwd");
    }

    @Override
    public String rememberDevice(Challenge challenge, Client client, Instant now, Instant expiresAt) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        String deviceId = client.platform() == Platform.WEB ? null : one(db.query("select device_id from auth_challenges where id=?",
                (rs, n) -> rs.getString(1), challenge.id()));
        if (client.platform() != Platform.WEB && (deviceId == null || deviceId.isBlank())) return null;
        String secret = client.platform() == Platform.WEB ? null : crypto.newNativeBinding();
        if (context != null) {
            db.update("delete from trusted_devices where user_id=? and client_id=? and platform='WEB' and browser_context_id=?",
                    challenge.user().id(), client.clientId(), context);
        } else {
            db.update("delete from trusted_devices where user_id=? and client_id=? and platform=? and device_id=?",
                    challenge.user().id(), client.clientId(), client.platform().name(), deviceId);
        }
        db.update("insert into trusted_devices(id,user_id,client_id,platform,browser_context_id,device_id,secret_hash,auth_version,created_at,expires_at) values (?,?,?,?,?,?,?,?,?,?)",
                UUID.randomUUID(), challenge.user().id(), client.clientId(), client.platform().name(), context, deviceId,
                secret == null ? null : crypto.hashBinding(secret), challenge.authVersion(), ts(now), ts(expiresAt));
        return secret;
    }

    @Override
    public void enqueueOtp(Challenge challenge, String otp, Instant now) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeUTF(challenge.user().email());
                output.writeUTF(otp);
            }
            byte[] ciphertext = outboxCipher.encrypt(bytes.toByteArray(), challenge.id().toString().getBytes(StandardCharsets.US_ASCII));
            db.update("insert into notification_outbox(id,challenge_id,purpose,generation,encrypted_payload,key_id,expires_at,status,attempts,next_attempt_at,created_at) values (?,?,'LOGIN_OTP',?,?,?,?,'PENDING',0,?,?)",
                    UUID.randomUUID(), challenge.id(), challenge.generation(), ciphertext, keyId, ts(challenge.expiresAt()), ts(now), ts(now));
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot encode email", ex);
        }
    }

    @Override
    public void incrementAttempts(Challenge challenge) {
        db.update("update auth_challenges set attempts=attempts+1 where id=?", challenge.id());
    }

    @Override
    public void resendOtp(Challenge challenge, byte[] mac, Instant now, Instant expires) {
        db.update("update auth_challenges set otp_mac=?,generation=generation+1,last_sent_at=?,expires_at=? where id=?", mac, ts(now), ts(expires), challenge.id());
    }

    @Override
    public Tokens complete(Challenge challenge, Client client, Instant now) {
        UUID context = client.platform() == Platform.WEB ? lockContext(client) : null;
        db.update("update auth_challenges set consumed_at=? where id=?", ts(now), challenge.id());
        return issuer.issue(challenge.user().id(), challenge.authVersion(), client, context, now, "pwd otp", challenge.id());
    }

    @Override
    public void checkPasswordLimit(String username, String ip) {
        limits.checkPassword(username, ip);
    }

    @Override
    public void recordPasswordFailure(String username, String ip) {
        limits.passwordFailure();
    }

    @Override
    public void passwordSucceeded() {
        limits.passwordSuccess();
    }

    @Override
    public void checkOtpLimit(UUID userId, UUID challengeId) {
        limits.checkOtp(userId, challengeId);
    }

    @Override
    public void recordOtpFailure(UUID userId, UUID challengeId) {
        limits.otpFailure();
    }

    @Override
    public void otpSucceeded() {
        limits.otpSuccess();
    }

    @Override
    public void checkMailLimit(UUID userId) {
        limits.checkMail(userId);
    }
}
