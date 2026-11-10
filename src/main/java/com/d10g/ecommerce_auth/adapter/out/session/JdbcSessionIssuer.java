package com.d10g.ecommerce_auth.adapter.out.session;

import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.AccessTokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.ActiveSession;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Caller owns the transaction and has locked the WEB context and affected users in ID order.
 */
public final class JdbcSessionIssuer {
    private final JdbcTemplate db;
    private final OpaqueSecrets secrets;
    private final AccessTokens tokens;
    private final AuditPort audit;

    public JdbcSessionIssuer(JdbcTemplate db, OpaqueSecrets secrets, AccessTokens tokens) {
        this.db = Objects.requireNonNull(db);
        this.secrets = Objects.requireNonNull(secrets);
        this.tokens = Objects.requireNonNull(tokens);
        this.audit = new JdbcAuditRecorder(db, secrets);
    }

    public Tokens issue(UUID userId, long authVersion, Client client, UUID contextId, Instant now, String amr) {
        return issue(userId, authVersion, client, contextId, now, amr, null);
    }

    public Tokens issue(UUID userId, long authVersion, Client client, UUID contextId, Instant now, String amr, UUID challengeId) {
        boolean web = client.platform() == Platform.WEB;
        if (web != (contextId != null)) throw new IllegalArgumentException("Invalid browser context");
        String query = web
                ? "select id from sessions where status='ACTIVE' and platform='WEB' and (user_id=? or browser_context_id=?) order by id for update"
                : "select id from sessions where status='ACTIVE' and platform in ('ANDROID','IOS') and user_id=? order by id for update";
        Object[] args = web ? new Object[]{userId, contextId} : new Object[]{userId};
        List<UUID> previous = db.query(query, (rs, row) -> rs.getObject(1, UUID.class), args);
        Timestamp timestamp = Timestamp.from(now);
        for (UUID id : previous) {
            db.query("select id from refresh_tokens where session_id=? order by id for update", rs -> {
            }, id);
        }
        for (UUID id : previous) {
            UUID owner = db.queryForObject("select user_id from sessions where id=?", UUID.class, id);
            db.update("update sessions set status=case when expires_at<=? or last_refresh_at<=? then 'EXPIRED' else 'REVOKED' end, revoked_at=?, revocation_reason='REPLACED' where id=? and status='ACTIVE'",
                    timestamp, Timestamp.from(now.minus(Duration.ofDays(7))), timestamp, id);
            db.update("update refresh_tokens set revoked_at=coalesce(revoked_at,?) where session_id=?", timestamp, id);
            audit.record(AuditPort.EventType.SESSION_REPLACED, owner, id, AuditPort.Outcome.SUCCESS, null);
        }
        UUID sessionId = UUID.randomUUID();
        UUID tokenId = UUID.randomUUID();
        UUID familyId = UUID.randomUUID();
        Instant expires = now.plus(Duration.ofDays(30));
        String refresh = secrets.generate();
        var metadata = challengeId == null ? client.metadata() : db.query("select device_label,user_agent,masked_ip from auth_challenges where id=?", rs -> rs.next() ? new com.d10g.ecommerce_auth.application.session.SessionPorts.SessionMetadata(rs.getString(1), rs.getString(2), rs.getString(3)) : null, challengeId);
        db.update("insert into sessions(id,user_id,client_id,platform,browser_context_id,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at,device_label,user_agent,masked_ip) values (?,?,?,?,?,'ACTIVE',?,?,?,?,?,?,?,?,?,?)",
                sessionId, userId, client.clientId(), client.platform().name(), contextId, authVersion,
                timestamp, amr, timestamp, timestamp, timestamp, Timestamp.from(expires), metadata == null ? null : metadata.deviceLabel(), metadata == null ? null : metadata.userAgent(), metadata == null ? null : metadata.maskedIp());
        db.update("insert into refresh_tokens(id,session_id,family_id,token_hash,issued_at,expires_at) values (?,?,?,?,?,?)",
                tokenId, sessionId, familyId, secrets.sha256(refresh), timestamp, Timestamp.from(expires));
        ActiveSession session = new ActiveSession(userId, sessionId, client.clientId(), client.platform(), authVersion,
                now, amr, expires, now, true, true, authVersion);
        String access = tokens.sign(session, now, now.plus(Duration.ofMinutes(5)));
        audit.record(AuditPort.EventType.LOGIN_SUCCESS, userId, sessionId, AuditPort.Outcome.SUCCESS, null);
        return new Tokens(access, refresh, sessionId, 5 * 60 * 60);
    }
}
