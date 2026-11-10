package com.d10g.ecommerce_auth.adapter.out.google;

import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionIssuer;
import com.d10g.ecommerce_auth.application.google.GoogleFlow;
import com.d10g.ecommerce_auth.application.google.GoogleIdentityPolicy;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.nimbusds.jwt.SignedJWT;

import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Google flow adapter. All session creation uses the shared issuer inside a single transaction.
 */
public final class JdbcGoogleFlow implements GoogleFlow {
    private final JdbcTemplate db;
    private final TransactionTemplate tx;
    private final OpaqueSecrets secrets;
    private final GoogleIdTokenVerifier verifier;
    private final JdbcSessionIssuer issuer;
    private final Map<String, Registration> registrations;
    private final AuditPort audit;
    public JdbcGoogleFlow(JdbcTemplate db, TransactionTemplate tx, OpaqueSecrets secrets, GoogleIdTokenVerifier verifier,
                          JdbcSessionIssuer issuer, Map<String, Registration> registrations) {
        this.db = Objects.requireNonNull(db);
        this.tx = Objects.requireNonNull(tx);
        this.secrets = Objects.requireNonNull(secrets);
        this.verifier = Objects.requireNonNull(verifier);
        this.issuer = Objects.requireNonNull(issuer);
        this.registrations = Map.copyOf(registrations);
        this.audit = new JdbcAuditRecorder(db, secrets);
    }

    private static User user(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new User(rs.getObject("id", UUID.class), rs.getString("status"), rs.getLong("auth_version"), instant(rs.getTimestamp("revoked_before")), instant(rs.getTimestamp("registration_expires_at")));
    }

    private static String normalizeEmail(String value) {
        if (value == null) return null;
        String v = value.trim().toLowerCase(java.util.Locale.ROOT);
        return v.length() <= 320 && v.contains("@") ? v : null;
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private static <T> T one(List<T> rows) {
        return rows.isEmpty() ? null : rows.get(0);
    }

    private static Result result(Status status) {
        return new Result(status, null, 0);
    }

    @Override
    public Challenge challenge(Client client, Principal principal) {
        if (!registered(client)) return new Challenge(Status.INVALID, null, null, null, null);
        return tx.execute(s -> {
            UUID context = lockContext(client);
            if (client.platform() == Platform.WEB && context == null)
                return new Challenge(Status.INVALID, null, null, null, null);
            long version = 0;
            User user = principal == null ? null : lockUser(principal.userId());
            Instant now = now();
            if (principal != null) {
                if (user == null || !"ACTIVE".equals(user.status()) || !recentSession(principal, client, context, now))
                    return new Challenge(Status.REAUTHENTICATION_REQUIRED, null, null, null, null);
                version = user.version();
            }
            UUID id = UUID.randomUUID();
            String nonce = secrets.generate();
            String binding = client.platform() == Platform.WEB ? null : secrets.generate();
            Instant expires = now.plus(Duration.ofMinutes(5));
            var metadata = client.metadata();
            db.update("insert into auth_challenges(id,purpose,user_id,session_id,client_id,browser_context_id,binding_hash,nonce_hash,auth_version,created_at,expires_at,device_label,user_agent,masked_ip) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    id, principal == null ? "GOOGLE_LOGIN" : "GOOGLE_LINK", principal == null ? null : principal.userId(),
                    principal == null ? null : principal.sessionId(), client.clientId(), context,
                    binding == null ? null : secrets.sha256(binding), secrets.sha256(nonce), principal == null ? null : version,
                    Timestamp.from(now), Timestamp.from(expires), metadata == null ? null : metadata.deviceLabel(), metadata == null ? null : metadata.userAgent(), metadata == null ? null : metadata.maskedIp());
            return new Challenge(Status.SUCCESS, id, nonce, binding, expires);
        });
    }

    @Override
    public Result exchange(Client client, UUID challengeId, String binding, String token) {
        return finish(client, null, challengeId, binding, token);
    }

    @Override
    public Result link(Client client, Principal principal, UUID challengeId, String binding, String token) {
        if (principal == null) return result(Status.INVALID);
        return finish(client, principal, challengeId, binding, token);
    }

    private Result finish(Client client, Principal principal, UUID id, String binding, String token) {
        if (!registered(client) || id == null || token == null) return result(Status.INVALID);
        Flow snapshot = flow(id, false);
        if (snapshot == null || !bound(snapshot, client, binding)) return result(Status.INVALID);
        GoogleIdTokenVerifier.Identity identity;
        try {
            String nonce = SignedJWT.parse(token).getJWTClaimsSet().getStringClaim("nonce");
            if (nonce == null || !secrets.matches(snapshot.nonceHash(), secrets.sha256(nonce)))
                return result(Status.INVALID);
            identity = verifier.verify(token, nonce, registrations.get(client.clientId()).google());
        } catch (java.text.ParseException e) {
            return result(Status.INVALID);
        } catch (JwtException e) {
            for (Throwable cause = e; cause != null; cause = cause.getCause()) {
                if (cause instanceof java.io.IOException || cause instanceof org.springframework.web.client.RestClientException)
                    throw new GoogleKeysUnavailableException(e);
            }
            return result(Status.INVALID);
        }
        if (identity.subject() == null || identity.subject().isBlank()) return result(Status.INVALID);
        return tx.execute(s -> finishLocked(client, principal, binding, snapshot, identity));
    }

    private Result finishLocked(Client client, Principal principal, String binding, Flow snapshot, GoogleIdTokenVerifier.Identity identity) {
        UUID context = lockContext(client);
        if (client.platform() == Platform.WEB && context == null) return result(Status.INVALID);
        String email = normalizeEmail(identity.contactEmail());
        advisory("google:" + identity.subject());
        if (email != null) advisory("email:" + email);
        UUID identityUser = one(db.query("select user_id from external_identities where provider='GOOGLE' and provider_subject=?", (rs, n) -> rs.getObject(1, UUID.class), identity.subject()));
        UUID emailUser = email == null ? null : one(db.query("select id from users where email=?", (rs, n) -> rs.getObject(1, UUID.class), email));
        UUID contextUser = context == null ? null : one(db.query("select user_id from sessions where browser_context_id=? and platform='WEB' and status='ACTIVE'", (rs, n) -> rs.getObject(1, UUID.class), context));
        List<UUID> ids = new ArrayList<>();
        for (UUID id : new UUID[]{identityUser, emailUser, contextUser, principal == null ? null : principal.userId()})
            if (id != null && !ids.contains(id)) ids.add(id);
        ids.sort(java.util.Comparator.comparing(UUID::toString));
        for (UUID id : ids) lockUser(id);
        Flow flow = flow(snapshot.id(), true);
        Instant now = now();
        if (flow == null || !bound(flow, client, binding) || !Objects.equals(flow.contextId(), context)
                || !secrets.matches(flow.nonceHash(), snapshot.nonceHash()) || flow.consumed() || flow.superseded())
            return result(Status.INVALID);
        if (!now.isBefore(flow.expires())) return result(Status.EXPIRED);
        String expectedPurpose = principal == null ? "GOOGLE_LOGIN" : "GOOGLE_LINK";
        if (!expectedPurpose.equals(flow.purpose())) return result(Status.INVALID);
        if (principal != null) {
            User user = readUser(principal.userId());
            if (!principal.userId().equals(flow.userId()) || !principal.sessionId().equals(flow.sessionId()) || user == null
                    || !GoogleIdentityPolicy.mayLink(user.status(), user.version(), flow.authVersion(), user.revokedBefore(), flow.created())
                    || !recentSession(principal, client, context, now)) return result(Status.REAUTHENTICATION_REQUIRED);
            if (identityUser != null && !identityUser.equals(principal.userId()))
                return result(Status.IDENTITY_CONFLICT);
            if (identityUser == null) {
                insertIdentity(principal.userId(), identity.subject(), now);
                audit.record(AuditPort.EventType.IDENTITY_LINK, principal.userId(), principal.sessionId(), AuditPort.Outcome.SUCCESS, null);
            }
            consume(flow.id(), now);
            return result(Status.SUCCESS);
        }
        User user;
        if (identityUser != null) {
            user = readUser(identityUser);
            if (user == null || !GoogleIdentityPolicy.mayUseExistingIdentity(user.status(), user.revokedBefore(), flow.created()))
                return result(Status.INVALID);
        } else {
            if (email == null) return result(Status.INVALID);
            User existing = emailUser == null ? null : readUser(emailUser);
            if (existing != null) {
                var collision = GoogleIdentityPolicy.emailCollision(existing.status(), existing.pendingUntil(), now);
                if (collision.outcome() == GoogleIdentityPolicy.Collision.REGISTRATION_PENDING)
                    return new Result(Status.REGISTRATION_PENDING, null, collision.retryAfterSeconds());
                if (collision.outcome() == GoogleIdentityPolicy.Collision.RECLAIM_EXPIRED) {
                    db.update("delete from notification_outbox where challenge_id in (select id from auth_challenges where user_id=?)", existing.id());
                    db.update("delete from auth_challenges where user_id=?", existing.id());
                    db.update("delete from users where id=? and status='PENDING_VERIFICATION' and registration_expires_at<=clock_timestamp()", existing.id());
                } else return result(Status.ACCOUNT_LINK_REQUIRED);
            }
            UUID newId = UUID.randomUUID();
            db.update("insert into users(id,email,email_verified,status,auth_version,created_at,updated_at) values (?,?,false,'ACTIVE',0,?,?)", newId, email, Timestamp.from(now), Timestamp.from(now));
            insertIdentity(newId, identity.subject(), now);
            user = readUser(newId);
        }
        consume(flow.id(), now);
        return new Result(Status.SUCCESS, issuer.issue(user.id(), user.version(), client, context, now, "google", flow.id()), 0);
    }

    private boolean registered(Client c) {
        return c != null && registrations.containsKey(c.clientId()) && registrations.get(c.clientId()).platform() == c.platform();
    }

    private UUID lockContext(Client c) {
        return c.platform() != Platform.WEB || c.browserContextHash() == null ? null : one(db.query("select id from browser_contexts where secret_hash=? for update", (rs, n) -> rs.getObject(1, UUID.class), c.browserContextHash()));
    }

    private void advisory(String key) {
        db.query("select pg_advisory_xact_lock(hashtextextended(?,0))", rs -> {
        }, key);
    }

    private Instant now() {
        return db.queryForObject("select clock_timestamp()", Timestamp.class).toInstant();
    }

    private User lockUser(UUID id) {
        return one(db.query("select id,status,auth_version,revoked_before,registration_expires_at from users where id=? for update", (rs, n) -> user(rs), id));
    }

    private User readUser(UUID id) {
        return one(db.query("select id,status,auth_version,revoked_before,registration_expires_at from users where id=?", (rs, n) -> user(rs), id));
    }

    private Flow flow(UUID id, boolean lock) {
        return one(db.query("select * from auth_challenges where id=?" + (lock ? " for update" : ""), (rs, n) -> new Flow(rs.getObject("id", UUID.class), rs.getString("purpose"), rs.getObject("user_id", UUID.class), rs.getObject("session_id", UUID.class), rs.getString("client_id"), rs.getObject("browser_context_id", UUID.class), rs.getBytes("binding_hash"), rs.getBytes("nonce_hash"), (Long) rs.getObject("auth_version"), instant(rs.getTimestamp("created_at")), instant(rs.getTimestamp("expires_at")), rs.getTimestamp("consumed_at") != null, rs.getTimestamp("superseded_at") != null), id));
    }

    private boolean bound(Flow f, Client c, String binding) {
        return c.clientId().equals(f.clientId()) && (c.platform() == Platform.WEB ? f.contextId() != null && c.browserContextHash() != null : f.contextId() == null && binding != null && secrets.matches(f.bindingHash(), secrets.sha256(binding)));
    }

    private boolean recentSession(Principal p, Client client, UUID context, Instant now) {
        return !db.query("select s.id from sessions s join users u on u.id=s.user_id where s.id=? and s.user_id=? and s.client_id=? and s.platform=? and s.browser_context_id is not distinct from ? and s.status='ACTIVE' and u.status='ACTIVE' and s.auth_version=u.auth_version and s.expires_at>? and s.last_refresh_at>? and s.auth_time>=? for update of s", (rs, n) -> rs.getObject(1, UUID.class), p.sessionId(), p.userId(), client.clientId(), client.platform().name(), context, Timestamp.from(now), Timestamp.from(now.minus(Duration.ofDays(7))), Timestamp.from(now.minus(Duration.ofMinutes(5)))).isEmpty();
    }

    private void consume(UUID id, Instant now) {
        db.update("update auth_challenges set consumed_at=? where id=?", Timestamp.from(now), id);
    }

    private void insertIdentity(UUID id, String subject, Instant now) {
        db.update("insert into external_identities(id,user_id,provider,provider_subject,created_at,updated_at) values (?,?,'GOOGLE',?,?,?)", UUID.randomUUID(), id, subject, Timestamp.from(now), Timestamp.from(now));
    }

    public record Registration(Platform platform, GoogleIdTokenVerifier.Registration google) {
    }

    private record Flow(UUID id, String purpose, UUID userId, UUID sessionId, String clientId, UUID contextId,
                        byte[] bindingHash, byte[] nonceHash, Long authVersion, Instant created, Instant expires,
                        boolean consumed, boolean superseded) {
    }

    private record User(UUID id, String status, long version, Instant revokedBefore, Instant pendingUntil) {
    }
}
