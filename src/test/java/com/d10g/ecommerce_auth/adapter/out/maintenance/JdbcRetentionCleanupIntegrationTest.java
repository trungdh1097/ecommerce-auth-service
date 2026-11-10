package com.d10g.ecommerce_auth.adapter.out.maintenance;

import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcRetentionCleanupIntegrationTest {
    private static JdbcTemplate admin;
    private static JdbcTemplate db;
    private static TransactionTemplate tx;
    private static String schema;
    private static JdbcRetentionCleanup cleanup;
    private static final UUID USER = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID CHALLENGE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID MESSAGE = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID SESSION = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID TOKEN = UUID.fromString("55555555-5555-4555-8555-555555555555");

    @BeforeAll static void initialize() {
        String url = System.getenv("AUTH_TEST_DB_URL");
        String user = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres");
        String password = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        admin = new JdbcTemplate(new DriverManagerDataSource(url, user, password));
        schema = "clean_it_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("create schema " + schema);
        var ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema, user, password);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        db = new JdbcTemplate(ds);
        tx = new TransactionTemplate(new DataSourceTransactionManager(ds));
        cleanup = new JdbcRetentionCleanup(db, tx, 100, Duration.ofHours(24), Duration.ofDays(90), Duration.ofSeconds(60));
    }
    @AfterAll static void close() { if (admin != null && schema != null) admin.execute("drop schema " + schema + " cascade"); }
    @BeforeEach void clear() { db.execute("truncate audit_events, notification_outbox, auth_challenges, refresh_tokens, sessions, browser_contexts, external_identities, users cascade"); }

    private void createUser(String status) {
        db.update("insert into users(id,username,email,password_hash,email_verified,status,registration_expires_at,auth_version,created_at,updated_at) values (?,'alice','alice@example.test','hash',false,?,clock_timestamp()-interval '1 hour',0,clock_timestamp(),clock_timestamp())", USER, status);
    }
    private void createChallenge(String expiry) {
        db.update("insert into auth_challenges(id,purpose,user_id,token_hash,auth_version,expires_at,created_at) values (?,'VERIFY_EMAIL',?,'hash',0,clock_timestamp()+cast(? as interval),clock_timestamp()-interval '3 days')", CHALLENGE, USER, expiry);
        db.update("insert into notification_outbox(id,challenge_id,purpose,generation,encrypted_payload,key_id,expires_at,status,attempts,next_attempt_at,created_at) values (?,?,'VERIFY_EMAIL',1,?,'current',clock_timestamp()+interval '1 hour','PENDING',0,clock_timestamp(),clock_timestamp())", MESSAGE, CHALLENGE, new byte[]{1,2,3});
    }
    @Test void removesExpiredPendingAndPreservesAudit() {
        createUser("PENDING_VERIFICATION");
        createChallenge("1 hour");
        var audit = new JdbcAuditRecorder(db, new OpaqueSecrets());
        tx.executeWithoutResult(status -> audit.record(AuditPort.EventType.LOGIN_FAILURE, USER, null, AuditPort.Outcome.FAILURE, null));
        cleanup.runOnce();
        assertEquals(0, count("users"));
        assertEquals(0, count("auth_challenges"));
        assertEquals(0, count("notification_outbox"));
        assertEquals(1, count("audit_events"));
        assertNull(db.queryForObject("select user_id from audit_events", UUID.class));
    }
    @Test void expiresSecretsImmediatelyButKeepsChallengeFor24Hours() {
        createUser("ACTIVE");
        createChallenge("-1 hour");
        cleanup.runOnce();
        assertEquals(1, count("auth_challenges"));
        assertEquals("EXPIRED", db.queryForObject("select status from notification_outbox", String.class));
        assertNull(db.queryForObject("select encrypted_payload from notification_outbox", byte[].class));
        db.update("update auth_challenges set expires_at=clock_timestamp()-interval '25 hours'");
        cleanup.runOnce();
        assertEquals(0, count("auth_challenges"));
        assertEquals(0, count("notification_outbox"));
        assertEquals(1, count("users"));
    }
    @Test void keepsRefreshUntilExpiryPlusSkewAndRemovesOldAudit() {
        createUser("ACTIVE");
        db.update("insert into sessions(id,user_id,client_id,platform,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at,revoked_at) values (?,?,'android','ANDROID','REVOKED',0,clock_timestamp()-interval '100 days','pwd',clock_timestamp()-interval '100 days',clock_timestamp()-interval '100 days',clock_timestamp()-interval '100 days',clock_timestamp()-interval '95 days',clock_timestamp()-interval '95 days')", SESSION, USER);
        db.update("insert into refresh_tokens(id,session_id,family_id,token_hash,issued_at,expires_at) values (?,?,?,? ,clock_timestamp()-interval '100 days',clock_timestamp()+interval '1 hour')", TOKEN, SESSION, UUID.randomUUID(), new byte[]{1});
        db.update("insert into audit_events(id,event_type,user_id,result,created_at) values (?,?,?,'SUCCESS',clock_timestamp()-interval '91 days')", UUID.randomUUID(), "LOGOUT_ALL", USER);
        cleanup.runOnce();
        assertEquals(1, count("sessions"));
        assertEquals(1, count("refresh_tokens"));
        assertEquals(0, count("audit_events"));
        db.update("update refresh_tokens set expires_at=clock_timestamp()-interval '61 seconds'");
        cleanup.runOnce();
        assertEquals(0, count("sessions"));
        assertEquals(0, count("refresh_tokens"));
    }
    @Test void activeUserIsNotRemovedWhenVerificationHoldsLock() throws Exception {
        createUser("PENDING_VERIFICATION");
        var ready = new CountDownLatch(1);
        var finish = new CountDownLatch(1);
        var pool = Executors.newSingleThreadExecutor();
        try {
            var verified = pool.submit(() -> tx.executeWithoutResult(status -> {
                db.update("update users set status='ACTIVE',email_verified=true where id=?", USER);
                ready.countDown();
                try { if (!finish.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("timeout"); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
            }));
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            cleanup.runOnce();
            finish.countDown();
            verified.get(10, TimeUnit.SECONDS);
            cleanup.runOnce();
            assertEquals("ACTIVE", db.queryForObject("select status from users where id=?", String.class, USER));
        } finally { finish.countDown(); pool.shutdownNow(); }
    }
    @Test void auditRequiresTransactionAndNeverStoresRawSessionId() {
        createUser("ACTIVE");
        var recorder = new JdbcAuditRecorder(db, new OpaqueSecrets());
        assertThrows(IllegalStateException.class, () -> recorder.record(AuditPort.EventType.SESSION_REVOKED, USER, SESSION, AuditPort.Outcome.SUCCESS, null));
        tx.executeWithoutResult(status -> recorder.record(AuditPort.EventType.SESSION_REVOKED, USER, SESSION, AuditPort.Outcome.SUCCESS, "0123456789abcdef"));
        byte[] stored = db.queryForObject("select session_correlation_hash from audit_events", byte[].class);
        assertArrayEquals(new OpaqueSecrets().sha256(SESSION.toString()), stored);
    }
    private static int count(String table) { return db.queryForObject("select count(*) from " + table, Integer.class); }
}
