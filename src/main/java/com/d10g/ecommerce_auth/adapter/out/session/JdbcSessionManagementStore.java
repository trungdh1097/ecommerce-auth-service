package com.d10g.ecommerce_auth.adapter.out.session;

import com.d10g.ecommerce_auth.application.session.SessionManagementService;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.d10g.ecommerce_auth.application.session.SessionManagementService.Cursor;
import com.d10g.ecommerce_auth.application.session.SessionManagementService.Profile;
import com.d10g.ecommerce_auth.application.session.SessionManagementService.RevokeResult;
import com.d10g.ecommerce_auth.application.session.SessionManagementService.SessionItem;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * All mutation methods lock user first, followed by sessions and refresh tokens.
 */
public final class JdbcSessionManagementStore implements SessionManagementService.Store {
    private final JdbcTemplate db;
    private final TransactionTemplate transaction;
    private final AuditPort audit;

    public JdbcSessionManagementStore(JdbcTemplate db, TransactionTemplate transaction) {
        this.db = db;
        this.transaction = transaction;
        this.audit = new JdbcAuditRecorder(db, new OpaqueSecrets());
    }

    @Override
    public <T> T inTransaction(Supplier<T> work) {
        return transaction.execute(status -> work.get());
    }

    @Override
    public Profile findProfile(UUID userId) {
        var users = db.query("select id,username,email,email_verified,password_hash from users where id=? and status='ACTIVE'", (rs, n) -> {
            var methods = new ArrayList<String>();
            if (rs.getString("password_hash") != null) methods.add("PASSWORD");
            return new Profile(rs.getObject("id", UUID.class), rs.getString("username"), rs.getString("email"), rs.getBoolean("email_verified"), methods);
        }, userId);
        if (users.isEmpty()) return null;
        Profile profile = users.get(0);
        var methods = new ArrayList<>(profile.loginMethods());
        methods.addAll(db.query("select provider from external_identities where user_id=? order by provider", (rs, n) -> rs.getString(1), userId));
        return new Profile(profile.id(), profile.username(), profile.email(), profile.emailVerified(), methods);
    }

    @Override
    public List<SessionItem> list(UUID userId, UUID currentSession, Cursor cursor, int limit) {
        String base = "select id,platform,device_label,user_agent,masked_ip,created_at,last_seen_at,expires_at from sessions where user_id=? and status='ACTIVE' and expires_at>clock_timestamp() and last_refresh_at>clock_timestamp()-interval '7 days'";
        String tail = " order by created_at desc,id desc limit ?";
        var mapper = (org.springframework.jdbc.core.RowMapper<SessionItem>) (rs, n) -> new SessionItem(rs.getObject("id", UUID.class), rs.getString("platform"), rs.getString("device_label"), rs.getString("user_agent"), rs.getString("masked_ip"), rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("last_seen_at").toInstant(), rs.getTimestamp("expires_at").toInstant(), currentSession.equals(rs.getObject("id", UUID.class)));
        return cursor == null ? db.query(base + tail, mapper, userId, limit) : db.query(base + " and (created_at,id)<(?,?)" + tail, mapper, userId, Timestamp.from(cursor.createdAt()), cursor.id(), limit);
    }

    @Override
    public RevokeResult revoke(UUID userId, UUID sessionId) {
        if (!lockUser(userId)) return RevokeResult.NOT_FOUND;
        var sessions = db.query("select id from sessions where id=? and user_id=? for update", (rs, n) -> rs.getObject(1, UUID.class), sessionId, userId);
        if (sessions.isEmpty()) return RevokeResult.NOT_FOUND;
        db.query("select id from refresh_tokens where session_id=? order by id for update", rs -> {
        }, sessionId);
        int revoked = db.update("update sessions set status='REVOKED',revoked_at=coalesce(revoked_at,clock_timestamp()),revocation_reason=coalesce(revocation_reason,'USER_REVOKED') where id=? and status='ACTIVE'", sessionId);
        db.update("update refresh_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where session_id=?", sessionId);
        if (revoked > 0)
            audit.record(AuditPort.EventType.SESSION_REVOKED, userId, sessionId, AuditPort.Outcome.SUCCESS, null);
        return RevokeResult.REVOKED;
    }

    @Override
    public void revokeAll(UUID userId) {
        if (!lockUser(userId)) return;
        var sessions = db.query("select id from sessions where user_id=? order by id for update", (rs, n) -> rs.getObject(1, UUID.class), userId);
        for (UUID session : sessions)
            db.query("select id from refresh_tokens where session_id=? order by id for update", rs -> {
            }, session);
        db.update("update users set auth_version=auth_version+1,revoked_before=clock_timestamp(),updated_at=clock_timestamp() where id=?", userId);
        db.update("update sessions set status='REVOKED',revoked_at=coalesce(revoked_at,clock_timestamp()),revocation_reason=coalesce(revocation_reason,'LOGOUT_ALL') where user_id=? and status='ACTIVE'", userId);
        db.update("update refresh_tokens set revoked_at=coalesce(revoked_at,clock_timestamp()) where session_id in (select id from sessions where user_id=?)", userId);
        audit.record(AuditPort.EventType.LOGOUT_ALL, userId, null, AuditPort.Outcome.SUCCESS, null);
    }

    private boolean lockUser(UUID userId) {
        return !db.query("select id from users where id=? for update", (rs, n) -> rs.getObject(1, UUID.class), userId).isEmpty();
    }
}
