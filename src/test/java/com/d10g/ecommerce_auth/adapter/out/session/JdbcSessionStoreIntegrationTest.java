package com.d10g.ecommerce_auth.adapter.out.session;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;
import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.application.session.SessionService;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
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

/** Runs against an isolated temporary schema on a supplied PostgreSQL instance. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcSessionStoreIntegrationTest {
    private static final Instant NOW = Instant.parse("2026-01-10T12:00:00Z");
    private static final String ORIGINAL = "original-refresh-token";
    private static final UUID USER = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID SESSION = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID CONTEXT = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID TOKEN = UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID FAMILY = UUID.fromString("55555555-5555-4555-8555-555555555555");
    private static final byte[] CONTEXT_HASH = bytes("context");
    private static final Client WEB = new Client("web", Platform.WEB, CONTEXT_HASH);
    private static JdbcTemplate admin;
    private static JdbcTemplate jdbc;
    private static String schema;
    private static Transaction transaction;
    private static JdbcSessionStore store;
    private static final Secrets SECRETS = new Secrets() {
        public String newRefreshToken() { return UUID.randomUUID().toString(); }
        public byte[] hash(String value) { return bytes(value); }
    };
    private static final AccessTokens TOKENS = new AccessTokens() {
        public String sign(ActiveSession session, Instant issued, Instant expires) { return "signed"; }
        public VerifiedAccessToken verify(String token) { return null; }
    };

    @BeforeAll static void createSchema() {
        String url = System.getenv("AUTH_TEST_DB_URL");
        String username = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres");
        String password = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        DriverManagerDataSource adminDs = new DriverManagerDataSource(url, username, password);
        admin = new JdbcTemplate(adminDs);
        schema = "auth_it_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("CREATE SCHEMA " + schema);
        DriverManagerDataSource ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema, username, password);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        jdbc = new JdbcTemplate(ds);
        store = new JdbcSessionStore(jdbc);
        TransactionTemplate template = new TransactionTemplate(new DataSourceTransactionManager(ds));
        transaction = new Transaction() { public <T> T execute(Supplier<T> work) { return template.execute(status -> work.get()); } };
    }
    @AfterAll static void dropSchema() { if (admin != null && schema != null) admin.execute("DROP SCHEMA " + schema + " CASCADE"); }
    @BeforeEach void seed() {
        jdbc.execute("TRUNCATE refresh_tokens, sessions, browser_contexts, users CASCADE");
        jdbc.update("insert into users(id,username,email,password_hash,email_verified,status,auth_version,created_at,updated_at) values (?,?,?,?,true,'ACTIVE',0,?,?)", USER, "alice", "alice@example.test", "hash", ts(NOW), ts(NOW));
        jdbc.update("insert into browser_contexts(id,secret_hash,created_at,last_seen_at) values (?,?,?,?)", CONTEXT, CONTEXT_HASH, ts(NOW), ts(NOW));
        jdbc.update("insert into sessions(id,user_id,client_id,platform,browser_context_id,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at) values (?,?,'web','WEB',?,'ACTIVE',0,?,'password otp',?,?,?,?)", SESSION, USER, CONTEXT, ts(NOW), ts(NOW), ts(NOW), ts(NOW), ts(NOW.plusSeconds(86400)));
        jdbc.update("insert into refresh_tokens(id,session_id,family_id,token_hash,issued_at,expires_at) values (?,?,?,?,?,?)", TOKEN, SESSION, FAMILY, bytes(ORIGINAL), ts(NOW), ts(NOW.plusSeconds(86400)));
    }
    @Test void rotationAndReplayCommitRevocation() {
        SessionService service = service(TOKENS);
        var first = service.refresh(ORIGINAL, WEB, SESSION);
        assertEquals(SessionService.Status.SUCCESS, first.status());
        assertNotNull(jdbc.queryForObject("select used_at from refresh_tokens where id=?", java.sql.Timestamp.class, TOKEN));
        assertEquals(2, count("refresh_tokens"));
        assertEquals(SessionService.Status.REFRESH_REUSED, service.refresh(ORIGINAL, WEB, SESSION).status());
        assertEquals("REVOKED", jdbc.queryForObject("select status from sessions where id=?", String.class, SESSION));
        assertEquals(2, jdbc.queryForObject("select count(*) from refresh_tokens where revoked_at is not null", Integer.class));
        assertEquals(1, jdbc.queryForObject("select count(*) from audit_events where event_type='REFRESH_REUSE' and user_id=?", Integer.class, USER));
        assertNotNull(jdbc.queryForObject("select session_correlation_hash from audit_events where event_type='REFRESH_REUSE'", byte[].class));
    }
    @Test void activityTimestampIsThrottledToOneWritePerMinute() {
        store.markSeen(USER, SESSION);
        var first=jdbc.queryForObject("select last_seen_at from sessions where id=?",java.sql.Timestamp.class,SESSION);
        assertNotNull(first);
        store.markSeen(USER, SESSION);
        var second=jdbc.queryForObject("select last_seen_at from sessions where id=?",java.sql.Timestamp.class,SESSION);
        assertEquals(first,second);
    }
    @Test void failedSigningRollsBackRotation() {
        AccessTokens failing = new AccessTokens() {
            public String sign(ActiveSession s, Instant i, Instant e) { throw new IllegalStateException("sign failed"); }
            public VerifiedAccessToken verify(String token) { return null; }
        };
        assertThrows(IllegalStateException.class, () -> service(failing).refresh(ORIGINAL, WEB, SESSION));
        assertNull(jdbc.queryForObject("select used_at from refresh_tokens where id=?", java.sql.Timestamp.class, TOKEN));
        assertEquals(1, count("refresh_tokens"));
        assertEquals("ACTIVE", jdbc.queryForObject("select status from sessions where id=?", String.class, SESSION));
    }
    @Test void wrongContextClientAndExpectedSessionCannotRotateOrRevoke() {
        SessionService service = service(TOKENS);
        assertEquals(SessionService.Status.INVALID, service.refresh(ORIGINAL, new Client("web", Platform.WEB, bytes("wrong")), SESSION).status());
        assertEquals(SessionService.Status.INVALID, service.refresh(ORIGINAL, new Client("android", Platform.ANDROID, null), SESSION).status());
        assertEquals(SessionService.Status.SESSION_CONTEXT_CHANGED, service.refresh(ORIGINAL, WEB, UUID.randomUUID()).status());
        assertEquals(SessionService.Status.SESSION_CONTEXT_CHANGED, service.logout(ORIGINAL, WEB, UUID.randomUUID()));
        assertEquals(1, count("refresh_tokens"));
        assertNull(jdbc.queryForObject("select used_at from refresh_tokens where id=?", java.sql.Timestamp.class, TOKEN));
        assertEquals("ACTIVE", jdbc.queryForObject("select status from sessions where id=?", String.class, SESSION));
    }
    @Test void concurrentUseOfSameRefreshRevokesFamily() throws Exception {
        SessionService service = service(TOKENS);
        var start = new CountDownLatch(1);
        var pool = Executors.newFixedThreadPool(2);
        try {
            var one = pool.submit(() -> { start.await(); return service.refresh(ORIGINAL, WEB, SESSION).status(); });
            var two = pool.submit(() -> { start.await(); return service.refresh(ORIGINAL, WEB, SESSION).status(); });
            start.countDown();
            var statuses = java.util.Set.of(one.get(10, TimeUnit.SECONDS), two.get(10, TimeUnit.SECONDS));
            assertEquals(java.util.Set.of(SessionService.Status.SUCCESS, SessionService.Status.REFRESH_REUSED), statuses);
            assertEquals("REVOKED", jdbc.queryForObject("select status from sessions where id=?", String.class, SESSION));
            assertEquals(2, jdbc.queryForObject("select count(*) from refresh_tokens where revoked_at is not null", Integer.class));
        } finally { pool.shutdownNow(); }
    }
    private static SessionService service(AccessTokens tokens) { return new SessionService(transaction, store, SECRETS, tokens, Clock.fixed(NOW, ZoneOffset.UTC)); }
    private static int count(String table) { return jdbc.queryForObject("select count(*) from " + table, Integer.class); }
    private static byte[] bytes(String text) { return text.getBytes(StandardCharsets.UTF_8); }
    private static java.sql.Timestamp ts(Instant time) { return java.sql.Timestamp.from(time); }
}
