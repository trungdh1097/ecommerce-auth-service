package com.d10g.ecommerce_auth.adapter.out.maintenance;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Bounded, multi-instance cleanup. Expiry decisions are rechecked under PostgreSQL row locks.
 */
public final class JdbcRetentionCleanup {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;
    private final int batchSize;
    private final long challengeRetentionSeconds;
    private final long historyRetentionSeconds;
    private final long clockSkewSeconds;

    public JdbcRetentionCleanup(JdbcTemplate db, TransactionTemplate transaction, int batchSize,
                                Duration challengeRetention, Duration historyRetention, Duration clockSkew) {
        if (batchSize < 1 || batchSize > 1000 || challengeRetention == null || challengeRetention.compareTo(Duration.ofHours(24)) < 0
                || historyRetention == null || historyRetention.compareTo(Duration.ofDays(90)) < 0
                || clockSkew == null || clockSkew.compareTo(Duration.ofSeconds(60)) < 0) {
            throw new IllegalArgumentException("Invalid cleanup policy");
        }
        this.db = db;
        this.transaction = transaction;
        this.batchSize = batchSize;
        this.challengeRetentionSeconds = challengeRetention.toSeconds();
        this.historyRetentionSeconds = historyRetention.toSeconds();
        this.clockSkewSeconds = clockSkew.toSeconds();
    }

    @Scheduled(fixedDelayString = "${auth.cleanup.poll-interval:PT1H}")
    public void poll() {
        runOnce();
    }

    public void runOnce() {
        expiredPendingRegistrations();
        expiredSessions();
        expiredSecrets();
        oldChallenges();
        oldSessions();
        oldAuditEvents();
    }

    private void expiredPendingRegistrations() {
        List<UUID> ids = db.query("""
                select id from users where status='PENDING_VERIFICATION' and registration_expires_at <= clock_timestamp()
                order by registration_expires_at, id limit ?
                """, (rs, n) -> rs.getObject(1, UUID.class), batchSize);
        for (UUID id : ids)
            transaction.executeWithoutResult(status -> {
                if (!lockUser(id)) return;
                Boolean expired = db.queryForObject("""
                        select status='PENDING_VERIFICATION' and registration_expires_at <= clock_timestamp() from users where id=?
                        """, Boolean.class, id);
                if (!Boolean.TRUE.equals(expired)) return;
                db.query("select id from auth_challenges where user_id=? order by id for update", rs -> {
                }, id);
                db.update("delete from notification_outbox where challenge_id in (select id from auth_challenges where user_id=?)", id);
                db.update("delete from auth_challenges where user_id=?", id);
                db.update("delete from users where id=? and status='PENDING_VERIFICATION' and registration_expires_at <= clock_timestamp()", id);
                db.update("delete from account_roles where account_id=?", id);
            });
    }

    private void expiredSessions() {
        List<OwnedId> ids = db.query("""
                select id,user_id from sessions where status='ACTIVE'
                  and (expires_at <= clock_timestamp() or last_refresh_at + interval '7 days' <= clock_timestamp())
                order by expires_at,id limit ?
                """, (rs, n) -> new OwnedId(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class)), batchSize);
        for (OwnedId id : ids)
            transaction.executeWithoutResult(status -> {
                if (!lockUser(id.user()) || !lockSession(id.id())) return;
                int changed = db.update("""
                        update sessions set status='EXPIRED',
                            revoked_at=least(expires_at,last_refresh_at + interval '7 days'), revocation_reason='EXPIRED'
                        where id=? and user_id=? and status='ACTIVE'
                          and (expires_at <= clock_timestamp() or last_refresh_at + interval '7 days' <= clock_timestamp())
                        """, id.id(), id.user());
                if (changed != 0)
                    db.update("update refresh_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where session_id=?", id.id());
            });
    }

    private void expiredSecrets() {
        List<ChallengeOutbox> ids = db.query("""
                select o.id,o.challenge_id,c.user_id from notification_outbox o
                  join auth_challenges c on c.id=o.challenge_id
                where o.encrypted_payload is not null and (
                    o.expires_at <= clock_timestamp() or c.expires_at <= clock_timestamp()
                    or c.consumed_at is not null or c.superseded_at is not null
                    or o.generation <> c.generation or o.status in ('SENT','EXPIRED','FAILED'))
                order by o.created_at,o.id limit ?
                """, (rs, n) -> new ChallengeOutbox(rs.getObject("id", UUID.class), rs.getObject("challenge_id", UUID.class),
                rs.getObject("user_id", UUID.class)), batchSize);
        for (ChallengeOutbox id : ids)
            transaction.executeWithoutResult(status -> {
                if (id.user() != null && !lockUser(id.user())) return;
                if (!lockChallenge(id.challenge()) || !lockOutbox(id.id())) return;
                db.update("""
                        update notification_outbox o set encrypted_payload=null,
                            status=case when o.status in ('PENDING','PROCESSING') then 'EXPIRED' else o.status end
                        from auth_challenges c where o.id=? and o.challenge_id=c.id and o.encrypted_payload is not null and (
                            o.expires_at <= clock_timestamp() or c.expires_at <= clock_timestamp()
                            or c.consumed_at is not null or c.superseded_at is not null
                            or o.generation <> c.generation or o.status in ('SENT','EXPIRED','FAILED'))
                        """, id.id());
            });
    }

    private void oldChallenges() {
        List<OwnedId> ids = db.query("""
                        select id,user_id from auth_challenges where expires_at <= clock_timestamp() - (? * interval '1 second')
                        order by expires_at,id limit ?
                        """, (rs, n) -> new OwnedId(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class)),
                challengeRetentionSeconds, batchSize);
        for (OwnedId id : ids)
            transaction.executeWithoutResult(status -> {
                if (id.user() != null && !lockUser(id.user())) return;
                if (!lockChallenge(id.id())) return;
                Boolean old = db.queryForObject("select expires_at <= clock_timestamp() - (? * interval '1 second') from auth_challenges where id=?",
                        Boolean.class, challengeRetentionSeconds, id.id());
                if (!Boolean.TRUE.equals(old)) return;
                db.update("delete from notification_outbox where challenge_id=?", id.id());
                db.update("delete from auth_challenges where id=? and expires_at <= clock_timestamp() - (? * interval '1 second')", id.id(), challengeRetentionSeconds);
            });
    }

    private void oldSessions() {
        List<OwnedId> ids = db.query("""
                        select id,user_id from sessions where status in ('REVOKED','EXPIRED')
                          and coalesce(revoked_at,expires_at) <= clock_timestamp() - (? * interval '1 second')
                        order by coalesce(revoked_at,expires_at),id limit ?
                        """, (rs, n) -> new OwnedId(rs.getObject("id", UUID.class), rs.getObject("user_id", UUID.class)),
                historyRetentionSeconds, batchSize);
        for (OwnedId id : ids)
            transaction.executeWithoutResult(status -> {
                if (!lockUser(id.user()) || !lockSession(id.id())) return;
                Boolean removable = db.queryForObject("""
                        select status in ('REVOKED','EXPIRED')
                            and coalesce(revoked_at,expires_at) <= clock_timestamp() - (? * interval '1 second')
                            and not exists (select 1 from refresh_tokens t where t.session_id=s.id
                                and t.expires_at + (? * interval '1 second') > clock_timestamp())
                            and not exists (select 1 from auth_challenges c where c.session_id=s.id)
                        from sessions s where s.id=? and s.user_id=?
                        """, Boolean.class, historyRetentionSeconds, clockSkewSeconds, id.id(), id.user());
                if (!Boolean.TRUE.equals(removable)) return;
                db.update("delete from refresh_tokens where session_id=?", id.id());
                db.update("delete from sessions where id=? and user_id=?", id.id(), id.user());
            });
    }

    private void oldAuditEvents() {
        transaction.executeWithoutResult(status -> db.update("""
                delete from audit_events where id in (
                    select id from audit_events where created_at <= clock_timestamp() - (? * interval '1 second')
                    order by created_at,id for update skip locked limit ?)
                """, historyRetentionSeconds, batchSize));
    }

    private boolean lockUser(UUID id) {
        return !db.query("select id from users where id=? for update skip locked", (rs, n) -> rs.getObject(1, UUID.class), id).isEmpty();
    }

    private boolean lockSession(UUID id) {
        return !db.query("select id from sessions where id=? for update skip locked", (rs, n) -> rs.getObject(1, UUID.class), id).isEmpty();
    }

    private boolean lockChallenge(UUID id) {
        return !db.query("select id from auth_challenges where id=? for update skip locked", (rs, n) -> rs.getObject(1, UUID.class), id).isEmpty();
    }

    private boolean lockOutbox(UUID id) {
        return !db.query("select id from notification_outbox where id=? for update skip locked", (rs, n) -> rs.getObject(1, UUID.class), id).isEmpty();
    }

    private record OwnedId(UUID id, UUID user) {
    }

    private record ChallengeOutbox(UUID id, UUID challenge, UUID user) {
    }
}
