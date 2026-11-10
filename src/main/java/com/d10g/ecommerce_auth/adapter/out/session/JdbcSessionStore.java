package com.d10g.ecommerce_auth.adapter.out.session;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;

import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * PostgreSQL-backed session operations. The caller must own the transaction.
 */
public final class JdbcSessionStore implements Store {
    private final JdbcTemplate jdbc;
    private final AuditPort audit;

    public JdbcSessionStore(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
        this.audit = new JdbcAuditRecorder(jdbc, new OpaqueSecrets());
    }

    private static ActiveSession readSession(ResultSet rs) throws SQLException {
        return new ActiveSession(uuid(rs, "user_id"), uuid(rs, "id"), rs.getString("client_id"),
                Platform.valueOf(rs.getString("platform")), rs.getLong("auth_version"), time(rs, "auth_time"), rs.getString("amr"),
                time(rs, "expires_at"), time(rs, "last_refresh_at"), "ACTIVE".equals(rs.getString("status")),
                "ACTIVE".equals(rs.getString("user_status")), rs.getLong("current_auth_version"));
    }

    private static UUID uuid(ResultSet rs, String col) throws SQLException {
        return rs.getObject(col, UUID.class);
    }

    private static Instant time(ResultSet rs, String col) throws SQLException {
        var value = rs.getTimestamp(col);
        return value == null ? null : value.toInstant();
    }

    private static <T> T one(List<T> values) {
        return values.isEmpty() ? null : values.get(0);
    }

    @Override
    public LockedCredential lockCredential(byte[] tokenHash, Client client) {
        UUID contextId = null;
        if (client.platform() == Platform.WEB) {
            if (client.browserContextHash() == null) return null;
            contextId = one(jdbc.query("select id from browser_contexts where secret_hash = ? for update",
                    (rs, n) -> uuid(rs, "id"), client.browserContextHash()));
            if (contextId == null) return null;
        }
        var ids = one(jdbc.query("select s.user_id, s.id session_id, t.id token_id from refresh_tokens t join sessions s on s.id=t.session_id where t.token_hash=?",
                (rs, n) -> new Ids(uuid(rs, "user_id"), uuid(rs, "session_id"), uuid(rs, "token_id")), tokenHash));
        if (ids == null) return null;
        // Lock ordering is context -> user -> session -> token. Queries recheck data after waiting.
        if (jdbc.query("select id from users where id=? for update", (rs, n) -> uuid(rs, "id"), ids.user()).isEmpty())
            return null;
        var session = one(jdbc.query("select s.*, u.status user_status, u.auth_version current_auth_version from sessions s join users u on u.id=s.user_id where s.id=? and s.user_id=? for update of s",
                (rs, n) -> readSession(rs), ids.session(), ids.user()));
        if (session == null) return null;
        if (client.platform() == Platform.WEB) {
            var actualContext = one(jdbc.query("select browser_context_id from sessions where id=?", (rs, n) -> uuid(rs, "browser_context_id"), ids.session()));
            if (!contextId.equals(actualContext)) return null;
        }
        return one(jdbc.query("select id, family_id, expires_at, used_at, revoked_at from refresh_tokens where id=? and session_id=? and token_hash=? for update",
                (rs, n) -> new LockedCredential(session, uuid(rs, "id"), uuid(rs, "family_id"),
                        time(rs, "expires_at"), time(rs, "used_at"), time(rs, "revoked_at")), ids.token(), ids.session(), tokenHash));
    }

    @Override
    public void rotate(LockedCredential credential, UUID tokenId, byte[] tokenHash, Instant now) {
        jdbc.update("update refresh_tokens set used_at=? where id=?", java.sql.Timestamp.from(now), credential.tokenId());
        jdbc.update("insert into refresh_tokens(id, session_id, family_id, token_hash, parent_id, issued_at, expires_at) values (?,?,?,?,?,?,?)",
                tokenId, credential.session().sessionId(), credential.familyId(), tokenHash, credential.tokenId(),
                java.sql.Timestamp.from(now), java.sql.Timestamp.from(credential.session().expiresAt()));
        jdbc.update("update sessions set last_refresh_at=?, last_seen_at=? where id=?", java.sql.Timestamp.from(now), java.sql.Timestamp.from(now), credential.session().sessionId());
    }

    @Override
    public void revoke(LockedCredential credential, Instant now, String reason) {
        int revoked = jdbc.update("update sessions set status='REVOKED', revoked_at=coalesce(revoked_at, ?), revocation_reason=coalesce(revocation_reason, ?) where id=? and status='ACTIVE'",
                java.sql.Timestamp.from(now), reason, credential.session().sessionId());
        jdbc.update("update refresh_tokens set revoked_at=coalesce(revoked_at, ?) where session_id=? and family_id=?",
                java.sql.Timestamp.from(now), credential.session().sessionId(), credential.familyId());
        if ("REFRESH_REUSED".equals(reason))
            audit.record(AuditPort.EventType.REFRESH_REUSE, credential.session().userId(), credential.session().sessionId(), AuditPort.Outcome.FAILURE, null);
        else if (revoked > 0)
            audit.record(AuditPort.EventType.SESSION_REVOKED, credential.session().userId(), credential.session().sessionId(), AuditPort.Outcome.SUCCESS, null);
    }

    @Override
    public ActiveSession findActive(UUID userId, UUID sessionId) {
        return one(jdbc.query("select s.*, u.status user_status, u.auth_version current_auth_version from sessions s join users u on u.id=s.user_id where s.id=? and s.user_id=?",
                (rs, n) -> readSession(rs), sessionId, userId));
    }

    @Override
    public void markSeen(UUID userId, UUID sessionId) {
        jdbc.update("update sessions set last_seen_at=clock_timestamp() where id=? and user_id=? and status='ACTIVE' and last_seen_at<=clock_timestamp()-interval '1 minute'", sessionId, userId);
    }

    private record Ids(UUID user, UUID session, UUID token) {
    }
}
