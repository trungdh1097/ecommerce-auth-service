package com.d10g.ecommerce_auth.adapter.out.google;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionIssuer;
import com.d10g.ecommerce_auth.application.google.GoogleFlow;
import com.d10g.ecommerce_auth.application.session.SessionPorts.*;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcGoogleFlowIntegrationTest {
    private static JdbcTemplate admin, db;
    private static String schema;
    private static JdbcGoogleFlow flow;
    private static final OpaqueSecrets SECRETS = new OpaqueSecrets();
    private static final Client MOBILE = new Client("android", Platform.ANDROID, null);
    private static final byte[] KEY = "01234567890123456789012345678901".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    @BeforeAll static void setup() {
        String url = System.getenv("AUTH_TEST_DB_URL"), user = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres"), pass = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        admin = new JdbcTemplate(new DriverManagerDataSource(url, user, pass));
        schema = "google_it_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("create schema " + schema);
        var ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema, user, pass);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        db = new JdbcTemplate(ds);
        JwtDecoder decoder = raw -> {
            try {
                var c = SignedJWT.parse(raw).getJWTClaimsSet();
                return Jwt.withTokenValue(raw).header("alg", "RS256").claim("iss", c.getIssuer()).claim("sub", c.getSubject()).claim("aud", c.getAudience())
                        .claim("nonce", c.getStringClaim("nonce")).claim("email", c.getStringClaim("email"))
                        .issuedAt(c.getIssueTime().toInstant()).expiresAt(c.getExpirationTime().toInstant()).build();
            } catch (Exception e) { throw new IllegalArgumentException(e); }
        };
        AccessTokens signer = new AccessTokens() {
            public String sign(ActiveSession session, Instant issuedAt, Instant expiresAt) { return "signed"; }
            public VerifiedAccessToken verify(String raw) { return null; }
        };
        flow = new JdbcGoogleFlow(db, new TransactionTemplate(new DataSourceTransactionManager(ds)), SECRETS,
                new GoogleIdTokenVerifier(decoder, Clock.systemUTC(), Duration.ofSeconds(60)), new JdbcSessionIssuer(db, SECRETS, signer),
                Map.of("android", new JdbcGoogleFlow.Registration(Platform.ANDROID, new GoogleIdTokenVerifier.Registration("android-audience", Set.of()))));
    }
    @AfterAll static void cleanup() { if (admin != null && schema != null) admin.execute("drop schema " + schema + " cascade"); }
    @BeforeEach void clear() { db.execute("truncate notification_outbox, auth_challenges, refresh_tokens, sessions, external_identities, browser_contexts, users cascade"); }
    @Test void signupCreatesUnverifiedGoogleAccountAndReplacesMobileOnlyAfterSuccess() throws Exception {
        var c = flow.challenge(MOBILE, null);
        assertEquals(GoogleFlow.Status.SUCCESS, c.status());
        var result = flow.exchange(MOBILE, c.id(), c.nativeBinding(), token(c.nonce(), "subject", "user@example.test"));
        assertEquals(GoogleFlow.Status.SUCCESS, result.status());
        assertNotNull(result.tokens());
        assertEquals(Boolean.FALSE, db.queryForObject("select email_verified from users where email='user@example.test'", Boolean.class));
        assertEquals(1, db.queryForObject("select count(*) from sessions where status='ACTIVE'", Integer.class));
        assertEquals(GoogleFlow.Status.INVALID, flow.exchange(MOBILE, c.id(), c.nativeBinding(), token(c.nonce(), "subject", "user@example.test")).status());
        var next = flow.challenge(MOBILE, null);
        assertEquals(GoogleFlow.Status.SUCCESS, flow.exchange(MOBILE, next.id(), next.nativeBinding(), token(next.nonce(), "subject", "changed@example.test")).status());
        assertEquals(1, db.queryForObject("select count(*) from users", Integer.class));
        assertEquals("user@example.test", db.queryForObject("select email from users", String.class));
        assertEquals(1, db.queryForObject("select count(*) from sessions where status='ACTIVE'", Integer.class));
    }
    @Test void bindingNonceAndPendingCollisionPreserveExistingState() throws Exception {
        db.update("insert into users(id,username,email,password_hash,email_verified,status,registration_expires_at,created_at,updated_at) values (?,?,?, ?,false,'PENDING_VERIFICATION',clock_timestamp()+interval '1 hour',clock_timestamp(),clock_timestamp())", UUID.randomUUID(), "alice", "pending@example.test", "hash");
        var c = flow.challenge(MOBILE, null);
        String token = token(c.nonce(), "subject", "pending@example.test");
        assertEquals(GoogleFlow.Status.INVALID, flow.exchange(MOBILE, c.id(), "bad", token).status());
        assertEquals(GoogleFlow.Status.INVALID, flow.exchange(MOBILE, c.id(), c.nativeBinding(), token("wrong", "subject", "pending@example.test")).status());
        var result = flow.exchange(MOBILE, c.id(), c.nativeBinding(), token);
        assertEquals(GoogleFlow.Status.REGISTRATION_PENDING, result.status());
        assertTrue(result.retryAfterSeconds() > 0);
        assertEquals(0, db.queryForObject("select count(*) from sessions", Integer.class));
        assertEquals(0, db.queryForObject("select count(*) from external_identities", Integer.class));
    }
    @Test void activeEmailCollisionDoesNotLinkAccount() throws Exception {
        db.update("insert into users(id,email,email_verified,status,created_at,updated_at) values (?, ?,true,'ACTIVE',clock_timestamp(),clock_timestamp())", UUID.randomUUID(), "exists@example.test");
        var c = flow.challenge(MOBILE, null);
        assertEquals(GoogleFlow.Status.ACCOUNT_LINK_REQUIRED, flow.exchange(MOBILE, c.id(), c.nativeBinding(), token(c.nonce(), "new-subject", "exists@example.test")).status());
        assertEquals(0, db.queryForObject("select count(*) from external_identities", Integer.class));
    }
    @Test void linkRequiresRecentSessionAndNeverTransfersAnIdentity() throws Exception {
        var first = flow.challenge(MOBILE, null);
        var session = flow.exchange(MOBILE, first.id(), first.nativeBinding(), token(first.nonce(), "first", "one@example.test"));
        UUID userId = db.queryForObject("select id from users where email='one@example.test'", UUID.class);
        var principal = new GoogleFlow.Principal(userId, session.tokens().sessionId());
        var link = flow.challenge(MOBILE, principal);
        assertEquals(GoogleFlow.Status.SUCCESS, link.status());
        assertEquals(GoogleFlow.Status.SUCCESS, flow.link(MOBILE, principal, link.id(), link.nativeBinding(), token(link.nonce(), "second", "other@example.test")).status());
        assertEquals(1, db.queryForObject("select count(*) from audit_events where event_type='IDENTITY_LINK'", Integer.class));
        assertEquals(2, db.queryForObject("select count(*) from external_identities where user_id=?", Integer.class, userId));
        assertEquals(GoogleFlow.Status.INVALID, flow.link(MOBILE, principal, link.id(), link.nativeBinding(), token(link.nonce(), "third", "other@example.test")).status());
        db.update("update sessions set auth_time=clock_timestamp()-interval '6 minutes' where id=?", principal.sessionId());
        assertEquals(GoogleFlow.Status.REAUTHENTICATION_REQUIRED, flow.challenge(MOBILE, principal).status());
    }
    @Test void logoutAllRevocationInvalidatesAlreadyStartedGoogleFlow() throws Exception {
        var initial = flow.challenge(MOBILE, null);
        var login = flow.exchange(MOBILE, initial.id(), initial.nativeBinding(), token(initial.nonce(), "existing", "one@example.test"));
        var pending = flow.challenge(MOBILE, null);
        db.update("update users set auth_version=auth_version+1, revoked_before=clock_timestamp() where email='one@example.test'");
        assertEquals(GoogleFlow.Status.INVALID, flow.exchange(MOBILE, pending.id(), pending.nativeBinding(), token(pending.nonce(), "existing", "one@example.test")).status());
        assertEquals(1, db.queryForObject("select count(*) from sessions where id=?", Integer.class, login.tokens().sessionId()));
    }
    @Test void linkRecencyIsRecheckedAfterWaitingForUserLock() throws Exception {
        var first = flow.challenge(MOBILE, null);
        var login = flow.exchange(MOBILE, first.id(), first.nativeBinding(), token(first.nonce(), "subject", "wait@example.test"));
        UUID user = db.queryForObject("select id from users where email='wait@example.test'", UUID.class);
        UUID session = login.tokens().sessionId();
        db.update("update sessions set auth_time=clock_timestamp()-interval '4 minutes 58 seconds' where id=?", session);
        var locked = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        var executor = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            var lockFuture = executor.submit(() -> {
                db.execute((org.springframework.jdbc.core.ConnectionCallback<Void>) connection -> {
                    connection.setAutoCommit(false);
                    try (var statement = connection.prepareStatement("select id from users where id=? for update")) {
                        statement.setObject(1, user);
                        statement.executeQuery();
                        locked.countDown();
                        if (!release.await(10, java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("timed out waiting for release");
                        connection.commit();
                    } catch (InterruptedException ex) { Thread.currentThread().interrupt(); throw new IllegalStateException(ex); }
                    finally { connection.setAutoCommit(true); }
                    return null;
                });
            });
            assertTrue(locked.await(5, java.util.concurrent.TimeUnit.SECONDS));
            var attempt = executor.submit(() -> flow.challenge(MOBILE, new GoogleFlow.Principal(user, session)));
            Thread.sleep(2600);
            release.countDown();
            lockFuture.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertEquals(GoogleFlow.Status.REAUTHENTICATION_REQUIRED, attempt.get(5, java.util.concurrent.TimeUnit.SECONDS).status());
        } finally { release.countDown(); executor.shutdownNow(); }
    }
    private static String token(String nonce, String subject, String email) throws Exception {
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder().issuer("https://accounts.google.com").subject(subject).audience("android-audience").issueTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(300))).claim("nonce", nonce).claim("email", email).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        jwt.sign(new MACSigner(KEY));
        return jwt.serialize();
    }
}
