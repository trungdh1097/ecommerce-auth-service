package com.d10g.ecommerce_auth.adapter.out.account;

import com.d10g.ecommerce_auth.application.account.AccountPorts;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
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
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * PostgreSQL adapter; all state-changing port operations run in the caller's transaction.
 */
public final class JdbcAccountAdapter implements AccountPorts {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;
    private final PasswordEncoder passwords;
    private final OpaqueSecrets secrets;
    private final OutboxCipher cipher;
    private final String keyId;
    private final AuditPort audit;

    public JdbcAccountAdapter(JdbcTemplate db, TransactionTemplate transaction, PasswordEncoder passwords,
                              OpaqueSecrets secrets, OutboxCipher cipher, String keyId) {
        this.db = db;
        this.transaction = transaction;
        this.passwords = passwords;
        this.secrets = secrets;
        this.cipher = cipher;
        this.keyId = keyId;
        this.audit = new JdbcAuditRecorder(db, secrets);
    }

    @Override
    public void audit(AuditPort.EventType event, UUID userId) {
        audit.record(event, userId, null, AuditPort.Outcome.SUCCESS, null);
    }

    @Override
    public <T> T inTransaction(Supplier<T> work) {
        return transaction.execute(s -> work.get());
    }

    @Override
    public void lockRegistration(String username, String email) {
        java.util.List<String> keys = new java.util.ArrayList<>(java.util.List.of("email:" + email, "username:" + username));
        java.util.Collections.sort(keys);
        for (String key : keys)
            db.query("select pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> {
            }, key);
        db.query("select id from users where username = ? or email = ? order by id for update", rs -> {
        }, username, email);
    }

    @Override
    public Instant databaseTime() {
        return db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
    }

    private Optional<Account> findAccount(String sql, Object id) {
        List<Account> rows = db.query(sql, (rs, n) -> account(rs), id);
        return rows.stream().findFirst();
    }

    private Account account(ResultSet rs) throws SQLException {
        Timestamp expires = rs.getTimestamp("registration_expires_at");
        return new Account(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("email"),
                rs.getString("password_hash"), rs.getBoolean("email_verified"),
                Account.Status.valueOf(rs.getString("status")), expires == null ? null : expires.toInstant(), rs.getLong("auth_version"));
    }

    @Override
    public Optional<Account> lockById(UUID id) {
        return findAccount("select * from users where id = ? for update", id);
    }

    @Override
    public Optional<SessionAuthentication> lockAuthenticatedSession(UUID userId, UUID sessionId, long authVersion) {
        if (sessionId == null) return Optional.empty();
        return db.query("select auth_time,expires_at,last_refresh_at,amr from sessions where id=? and user_id=? and status='ACTIVE' and auth_version=? for update",
                (rs, n) -> new SessionAuthentication(rs.getTimestamp("auth_time").toInstant(), rs.getTimestamp("expires_at").toInstant(), rs.getTimestamp("last_refresh_at").toInstant(), rs.getString("amr")),
                sessionId, userId, authVersion).stream().findFirst();
    }

    @Override
    public Optional<Account> lockByUsername(String value) {
        return findAccount("select * from users where username = ? for update", value);
    }

    @Override
    public Optional<Account> lockByEmail(String value) {
        return findAccount("select * from users where email = ? for update", value);
    }

    @Override
    public void deleteExpiredPending(Account account) {
        db.update("delete from notification_outbox where challenge_id in (select id from auth_challenges where user_id = ?)", account.id());
        db.update("delete from auth_challenges where user_id = ?", account.id());
        db.update("delete from users where id = ? and status = 'PENDING_VERIFICATION' and registration_expires_at <= clock_timestamp()", account.id());
    }

    @Override
    public void insertPending(UUID id, String username, String email, String passwordHash, Instant now, Instant expiry) {
        try {
            db.update("insert into users(id,username,email,password_hash,email_verified,status,registration_expires_at,auth_version,created_at,updated_at) values (?,?,?,?,false,'PENDING_VERIFICATION',?,0,?,?)", id, username, email, passwordHash, Timestamp.from(expiry), Timestamp.from(now), Timestamp.from(now));
        } catch (DuplicateKeyException e) {
            throw new RegistrationConflict(e);
        }
    }

    private Optional<Challenge> find(String sql, Object... args) {
        return db.query(sql, (rs, n) -> new Challenge(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class),
                Purpose.valueOf(rs.getString("purpose")), rs.getLong("auth_version"), rs.getTimestamp("expires_at").toInstant(),
                rs.getTimestamp("consumed_at") != null, rs.getTimestamp("superseded_at") != null), args).stream().findFirst();
    }

    @Override
    public Optional<Challenge> findChallenge(String hash, Purpose purpose) {
        return find("select * from auth_challenges where token_hash = ? and purpose = ?", hash, purpose.name());
    }

    @Override
    public Optional<Challenge> lockChallenge(UUID id) {
        return find("select * from auth_challenges where id = ? for update", id);
    }

    @Override
    public void supersedeChallenges(UUID userId, Purpose purpose, Instant now) {
        db.update("update auth_challenges set superseded_at = ? where user_id = ? and purpose = ? and consumed_at is null and superseded_at is null", Timestamp.from(now), userId, purpose.name());
    }

    @Override
    public void insertChallenge(UUID id, UUID userId, Purpose purpose, String hash, long version, Instant now, Instant expiry) {
        db.update("insert into auth_challenges(id,purpose,user_id,token_hash,auth_version,expires_at,created_at) values (?,?,?,?,?,?,?)", id, purpose.name(), userId, hash, version, Timestamp.from(expiry), Timestamp.from(now));
    }

    @Override
    public void consumeChallenge(UUID id, Instant now) {
        db.update("update auth_challenges set consumed_at = ? where id = ?", Timestamp.from(now), id);
    }

    @Override
    public void markEmailVerified(UUID userId, Instant now) {
        db.update("update users set email_verified = true, status = case when status = 'PENDING_VERIFICATION' then 'ACTIVE' else status end, updated_at = ? where id = ?", Timestamp.from(now), userId);
    }

    @Override
    public void changePasswordAndRevoke(UUID id, String hash) {
        db.update("update users set password_hash = ?, auth_version = auth_version + 1, revoked_before = clock_timestamp(), updated_at = clock_timestamp() where id = ?", hash, id);
        db.update("update sessions set status = 'REVOKED', revoked_at = clock_timestamp(), revocation_reason = 'PASSWORD_CHANGED' where user_id = ? and status = 'ACTIVE'", id);
        db.update("update refresh_tokens set revoked_at = coalesce(revoked_at, clock_timestamp()) where session_id in (select id from sessions where user_id = ?)", id);
    }

    @Override
    public void enqueueEmail(UUID challengeId, UUID userId, String email, Purpose purpose, String token, Instant expiry) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(buffer)) {
                output.writeUTF(email);
                output.writeUTF(token);
            }
            byte[] payload = cipher.encrypt(buffer.toByteArray(), challengeId.toString().getBytes(StandardCharsets.US_ASCII));
            db.update("insert into notification_outbox(id,challenge_id,purpose,generation,encrypted_payload,key_id,expires_at,status,attempts,next_attempt_at,created_at) values (?,?,?,1,?,?,?,'PENDING',0,clock_timestamp(),clock_timestamp())", UUID.randomUUID(), challengeId, purpose.name(), payload, keyId, Timestamp.from(expiry));
        } catch (IOException e) {
            throw new IllegalStateException("Cannot encode mail payload", e);
        }
    }

    @Override
    public void insertUserRole(UUID accountId) {
        db.update("insert into account_roles (account_id, role_id) values (?, ?)", accountId, 2);
    }

    @Override
    public String hashPassword(String password) {
        return passwords.encode(password);
    }

    @Override
    public boolean passwordMatches(String password, String hash) {
        return password != null && passwords.matches(password, hash);
    }

    @Override
    public String newToken() {
        return secrets.generate();
    }

    @Override
    public String hashToken(String token) {
        return HexFormat.of().formatHex(secrets.sha256(token));
    }

}
