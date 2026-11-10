package com.d10g.ecommerce_auth.adapter.out.notification;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.MailException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Claims rows by locking user, challenge, then outbox. Each SMTP attempt owns a separate
 * transaction and holds those locks until the attempt is recorded. A crash after SMTP has
 * accepted mail but before commit can result in duplicate delivery.
 */
public final class EmailOutboxWorker {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;
    private final OutboxKeyRing keys;
    private final EmailNotificationSender sender;
    private final int batchSize;
    private final int maxAttempts;
    private final Duration retryDelay;

    public EmailOutboxWorker(JdbcTemplate db, TransactionTemplate transaction, OutboxKeyRing keys,
                             EmailNotificationSender sender, int batchSize, int maxAttempts, Duration retryDelay) {
        if (batchSize < 1 || batchSize > 1000 || maxAttempts < 1 || retryDelay == null || retryDelay.isNegative() || retryDelay.isZero()) {
            throw new IllegalArgumentException("Invalid outbox worker configuration");
        }
        this.db = db;
        this.transaction = transaction;
        this.keys = keys;
        this.sender = sender;
        this.batchSize = batchSize;
        this.maxAttempts = maxAttempts;
        this.retryDelay = retryDelay;
    }

    private static Row readRow(ResultSet rs) throws SQLException {
        return new Row(rs.getString("status"), rs.getString("purpose"), rs.getInt("generation"), rs.getBytes("encrypted_payload"),
                rs.getString("key_id"), time(rs, "expires_at"), rs.getInt("attempts"), time(rs, "next_attempt_at"),
                rs.getObject("user_id", UUID.class), rs.getString("challenge_purpose"), rs.getInt("challenge_generation"),
                time(rs, "challenge_expires_at"), time(rs, "consumed_at"), time(rs, "superseded_at"),
                rs.getObject("auth_version", Long.class), rs.getInt("challenge_attempts"), rs.getString("user_status"),
                rs.getBoolean("email_verified"), rs.getString("password_hash"), rs.getObject("current_auth_version", Long.class),
                time(rs, "registration_expires_at"), time(rs, "current_time"));
    }

    private static Instant time(ResultSet rs, String column) throws SQLException {
        Timestamp timestamp = rs.getTimestamp(column);
        return timestamp == null ? null : timestamp.toInstant();
    }

    @Scheduled(fixedDelayString = "${auth.outbox.poll-interval:PT5S}")
    public void poll() {
        runOnce();
    }

    /**
     * Returns the number of rows actually processed by this worker.
     */
    public int runOnce() {
        List<Candidate> candidates = db.query("""
                select o.id, o.challenge_id, c.user_id
                from notification_outbox o join auth_challenges c on c.id = o.challenge_id
                where o.status = 'PENDING' and (o.next_attempt_at <= clock_timestamp() or o.expires_at <= clock_timestamp()
                    or c.expires_at <= clock_timestamp() or c.consumed_at is not null or c.superseded_at is not null
                    or o.generation <> c.generation)
                order by o.next_attempt_at, o.id limit ?
                """, (rs, n) -> new Candidate(rs.getObject("id", UUID.class), rs.getObject("challenge_id", UUID.class),
                rs.getObject("user_id", UUID.class)), batchSize);
        int processed = 0;
        for (Candidate candidate : candidates) {
            Boolean handled = transaction.execute(status -> process(candidate));
            if (Boolean.TRUE.equals(handled)) processed++;
        }
        return processed;
    }

    private boolean process(Candidate candidate) {
        if (candidate.userId() != null && db.query("select id from users where id = ? for update skip locked",
                (rs, n) -> rs.getObject(1, UUID.class), candidate.userId()).isEmpty()) return false;
        if (db.query("select id from auth_challenges where id = ? for update skip locked",
                (rs, n) -> rs.getObject(1, UUID.class), candidate.challengeId()).isEmpty()) return false;
        if (db.query("select id from notification_outbox where id = ? for update skip locked",
                (rs, n) -> rs.getObject(1, UUID.class), candidate.id()).isEmpty()) return false;
        List<Row> rows = db.query("""
                select o.status, o.purpose, o.generation, o.encrypted_payload, o.key_id, o.expires_at,
                       o.attempts, o.next_attempt_at, c.user_id, c.purpose challenge_purpose,
                       c.generation challenge_generation, c.expires_at challenge_expires_at,
                       c.consumed_at, c.superseded_at, c.auth_version, c.attempts challenge_attempts,
                       u.status user_status, u.email_verified, u.password_hash, u.auth_version current_auth_version,
                       u.registration_expires_at, clock_timestamp() current_time
                from notification_outbox o join auth_challenges c on c.id = o.challenge_id
                left join users u on u.id = c.user_id where o.id = ? and c.id = ?
                """, (rs, n) -> readRow(rs), candidate.id(), candidate.challengeId());
        if (rows.isEmpty()) return false;
        Row row = rows.get(0);
        if (!"PENDING".equals(row.status())) return false;
        if (!row.eligible()) {
            db.update("update notification_outbox set status='EXPIRED', encrypted_payload=null where id=?", candidate.id());
            return true;
        }
        if (row.nextAttempt().isAfter(row.now())) return false;
        var cipher = keys.cipher(row.keyId());
        if (cipher == null) {
            retry(candidate.id(), row);
            return true;
        }
        final byte[] plain;
        try {
            plain = cipher.decrypt(row.payload(), candidate.challengeId().toString().getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException | RuntimeException ex) {
            fail(candidate.id());
            return true;
        }
        try (DataInputStream input = new DataInputStream(new ByteArrayInputStream(plain))) {
            if (plain.length > 4096) throw new IOException("Invalid payload size");
            String email = input.readUTF();
            String secret = input.readUTF();
            if (input.available() != 0) throw new IOException("Invalid payload");
            Instant beforeSend = db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
            if (!row.notExpiredAt(beforeSend)) {
                db.update("update notification_outbox set status='EXPIRED', encrypted_payload=null where id=?", candidate.id());
                return true;
            }
            sender.send(row.purpose(), email, secret);
            db.update("update notification_outbox set status='SENT', encrypted_payload=null, attempts=attempts+1 where id=?", candidate.id());
        } catch (MailException ex) {
            retry(candidate.id(), row);
        } catch (IOException | IllegalArgumentException ex) {
            fail(candidate.id());
        } finally {
            java.util.Arrays.fill(plain, (byte) 0);
        }
        return true;
    }

    private void retry(UUID id, Row row) {
        int attempts = row.attempts() + 1;
        if (attempts >= maxAttempts) {
            db.update("update notification_outbox set status='FAILED', encrypted_payload=null, attempts=? where id=?", attempts, id);
            return;
        }
        long multiplier = 1L << Math.min(attempts - 1, 10);
        long delaySeconds = Math.min(3600, Math.min(3600, retryDelay.getSeconds()) * multiplier);
        db.update("update notification_outbox set attempts=?, next_attempt_at=? where id=?",
                attempts, Timestamp.from(row.now().plusSeconds(Math.max(1, delaySeconds))), id);
    }

    private void fail(UUID id) {
        db.update("update notification_outbox set status='FAILED', encrypted_payload=null, attempts=attempts+1 where id=?", id);
    }

    private record Candidate(UUID id, UUID challengeId, UUID userId) {
    }

    private record Row(String status, String purpose, int generation, byte[] payload, String keyId,
                       Instant expiresAt, int attempts, Instant nextAttempt, UUID userId, String challengePurpose,
                       int challengeGeneration, Instant challengeExpiresAt, Instant consumedAt, Instant supersededAt,
                       Long authVersion, int challengeAttempts, String userStatus, boolean emailVerified,
                       String passwordHash, Long currentAuthVersion, Instant registrationExpiresAt, Instant now) {
        boolean notExpiredAt(Instant time) {
            return expiresAt != null && challengeExpiresAt != null && time.isBefore(expiresAt)
                    && time.isBefore(challengeExpiresAt)
                    && (!"PENDING_VERIFICATION".equals(userStatus) || (registrationExpiresAt != null && time.isBefore(registrationExpiresAt)));
        }

        boolean eligible() {
            if (userId == null || payload == null || !purpose.equals(challengePurpose) || generation != challengeGeneration
                    || consumedAt != null || supersededAt != null || !notExpiredAt(now) || "DISABLED".equals(userStatus))
                return false;
            return switch (purpose) {
                case "VERIFY_EMAIL" -> !emailVerified && ("ACTIVE".equals(userStatus)
                        || ("PENDING_VERIFICATION".equals(userStatus) && registrationExpiresAt != null && now.isBefore(registrationExpiresAt)));
                case "RESET_PASSWORD" -> "ACTIVE".equals(userStatus) && emailVerified && passwordHash != null
                        && authVersion != null && authVersion.equals(currentAuthVersion);
                case "LOGIN_OTP" -> "ACTIVE".equals(userStatus) && emailVerified && challengeAttempts < 5
                        && authVersion != null && authVersion.equals(currentAuthVersion);
                default -> false;
            };
        }
    }
}
