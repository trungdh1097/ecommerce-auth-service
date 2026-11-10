package com.d10g.ecommerce_auth.adapter.out.account;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.application.account.AccountService;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.d10g.ecommerce_auth.security.crypto.OutboxCipher;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Set;
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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.support.TransactionTemplate;

/** PostgreSQL integration checks using a per-run schema; supply AUTH_TEST_DB_URL to run. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class JdbcAccountAdapterIntegrationTest {
    private static JdbcTemplate admin, jdbc;
    private static DriverManagerDataSource dataSource;
    private static String schema;
    private static AccountService service;
    private static OutboxCipher cipher;
    private static final String EMAIL = "alice@example.test", PASSWORD = "a long enough password";

    @BeforeAll static void setup() {
        String url = System.getenv("AUTH_TEST_DB_URL");
        String user = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres");
        String password = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        admin = new JdbcTemplate(new DriverManagerDataSource(url, user, password));
        schema = "account_it_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("CREATE SCHEMA " + schema);
        var ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema, user, password);
        dataSource = ds;
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        jdbc = new JdbcTemplate(ds);
        cipher = new OutboxCipher(new byte[32]);
        PasswordEncoder encoder = new PasswordEncoder() {
            public String encode(CharSequence value) { return "test:" + value; }
            public boolean matches(CharSequence value, String hash) { return encode(value).equals(hash); }
        };
        service = new AccountService(new JdbcAccountAdapter(jdbc, new TransactionTemplate(new DataSourceTransactionManager(ds)), encoder, new OpaqueSecrets(), cipher, "test"));
    }
    @AfterAll static void cleanup() { if (admin != null && schema != null) admin.execute("DROP SCHEMA " + schema + " CASCADE"); }
    @BeforeEach void truncate() { jdbc.execute("TRUNCATE users CASCADE"); }

    @Test void registerVerifyAndResetRevokeSessions() throws Exception {
        assertEquals(AccountService.Result.ACCEPTED, service.register("Alice", EMAIL, PASSWORD));
        UUID user = userId();
        String verification = newestToken("VERIFY_EMAIL");
        assertEquals(AccountService.Result.OK, service.verifyEmail(verification));
        assertEquals(AccountService.Result.INVALID_TOKEN, service.verifyEmail(verification));
        assertEquals("ACTIVE", jdbc.queryForObject("select status from users where id=?", String.class, user));
        UUID session = UUID.randomUUID(), refresh = UUID.randomUUID();
        Timestamp now = Timestamp.from(Instant.now());
        Timestamp expiry = Timestamp.from(Instant.now().plusSeconds(3600));
        jdbc.update("insert into sessions(id,user_id,client_id,platform,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at) values (?,?,'android','ANDROID','ACTIVE',0,?,'password otp',?,?,?,?)", session, user, now, now, now, now, expiry);
        jdbc.update("insert into refresh_tokens(id,session_id,family_id,token_hash,issued_at,expires_at) values (?,?,?,?,?,?)", refresh, session, UUID.randomUUID(), new byte[]{1}, now, expiry);
        assertEquals(AccountService.Result.ACCEPTED, service.forgotPassword(EMAIL));
        String reset = newestToken("RESET_PASSWORD");
        assertEquals(AccountService.Result.OK, service.resetPassword(reset, "another long password"));
        assertEquals(AccountService.Result.INVALID_TOKEN, service.resetPassword(reset, "another long password"));
        assertEquals("REVOKED", jdbc.queryForObject("select status from sessions where id=?", String.class, session));
        assertNotNull(jdbc.queryForObject("select revoked_at from refresh_tokens where id=?", Timestamp.class, refresh));
        assertEquals(1L, jdbc.queryForObject("select auth_version from users where id=?", Long.class, user));
        assertNotNull(jdbc.queryForObject("select revoked_before from users where id=?", Timestamp.class, user));
        assertEquals(1, jdbc.queryForObject("select count(*) from audit_events where event_type='PASSWORD_RESET' and user_id=?", Integer.class, user));
    }

    @Test void expiredPendingIsReclaimedWithoutCleanup() throws Exception {
        service.register("alice", EMAIL, PASSWORD);
        UUID previous = userId();
        String oldToken = newestToken("VERIFY_EMAIL");
        expirePending();
        assertEquals(AccountService.Result.ACCEPTED, service.register("alice", EMAIL, "a different password"));
        assertNotEquals(previous, userId());
        assertEquals(AccountService.Result.INVALID_TOKEN, service.verifyEmail(oldToken));
        assertEquals(1, count("users"));
        assertEquals(1, count("auth_challenges"));
        assertEquals(1, count("notification_outbox"));
    }

    @Test void simultaneousRegistrationCannotCreateDuplicateUsers() throws Exception {
        var start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var first = executor.submit(() -> { start.await(); return service.register("alice", EMAIL, PASSWORD); });
            var second = executor.submit(() -> { start.await(); return service.register("alice", EMAIL, PASSWORD); });
            start.countDown();
            assertEquals(AccountService.Result.ACCEPTED, first.get(10, TimeUnit.SECONDS));
            assertEquals(AccountService.Result.ACCEPTED, second.get(10, TimeUnit.SECONDS));
            assertEquals(1, count("users"));
            assertEquals(1, count("notification_outbox"));
        } finally { executor.shutdownNow(); }
    }

    @Test void simultaneousVerificationCanConsumeOnlyOnce() throws Exception {
        service.register("alice", EMAIL, PASSWORD);
        String token = newestToken("VERIFY_EMAIL");
        var start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var first = executor.submit(() -> { start.await(); return service.verifyEmail(token); });
            var second = executor.submit(() -> { start.await(); return service.verifyEmail(token); });
            start.countDown();
            assertEquals(Set.of(AccountService.Result.OK, AccountService.Result.INVALID_TOKEN), Set.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)));
            assertEquals("ACTIVE", jdbc.queryForObject("select status from users", String.class));
        } finally { executor.shutdownNow(); }
    }

    @Test void concurrentReclaimAndVerificationDoNotActivateExpiredRegistration() throws Exception {
        service.register("alice", EMAIL, PASSWORD);
        UUID oldUser = userId();
        String token = newestToken("VERIFY_EMAIL");
        expirePending();
        var start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var verify = executor.submit(() -> { start.await(); return service.verifyEmail(token); });
            var register = executor.submit(() -> { start.await(); return service.register("alice", EMAIL, PASSWORD); });
            start.countDown();
            assertEquals(AccountService.Result.INVALID_TOKEN, verify.get(10, TimeUnit.SECONDS));
            assertEquals(AccountService.Result.ACCEPTED, register.get(10, TimeUnit.SECONDS));
            assertNotEquals(oldUser, userId());
            assertEquals("PENDING_VERIFICATION", jdbc.queryForObject("select status from users", String.class));
            assertEquals(1, count("users"));
        } finally { executor.shutdownNow(); }
    }
    @Test void resendWaitingForUserLockPastExpiryDoesNotCreateEmail() throws Exception {
        service.register("alice", EMAIL, PASSWORD);
        UUID user = userId();
        var executor = Executors.newSingleThreadExecutor();
        try (var connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var statement = connection.prepareStatement("update users set registration_expires_at=clock_timestamp()+interval '1 second' where id=?")) {
                statement.setObject(1, user);
                statement.executeUpdate();
            }
            var future = executor.submit(() -> service.resendVerification(EMAIL));
            awaitBlockedAccountQuery();
            // Hold the row lock beyond the pending expiry assigned above.
            Thread.sleep(1200);
            connection.commit();
            assertEquals(AccountService.Result.ACCEPTED, future.get(10, TimeUnit.SECONDS));
            assertEquals(1, count("notification_outbox"));
            assertEquals(1, count("auth_challenges"));
        } finally { executor.shutdownNow(); }
    }

    @Test void passwordChangeWaitingForUserLockRechecksRecentAuthentication() throws Exception {
        service.register("alice", EMAIL, PASSWORD);
        assertEquals(AccountService.Result.OK, service.verifyEmail(newestToken("VERIFY_EMAIL")));
        UUID user = userId();
        Instant authenticatedAt = Instant.now().minusSeconds(299);
        UUID session = UUID.randomUUID();
        Timestamp now = Timestamp.from(Instant.now());
        jdbc.update("insert into sessions(id,user_id,client_id,platform,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at) values (?,?,'android','ANDROID','ACTIVE',0,?,'password otp',?,?,?,?)", session, user, Timestamp.from(authenticatedAt), now, now, now, Timestamp.from(Instant.now().plusSeconds(3600)));
        var executor = Executors.newSingleThreadExecutor();
        try (var connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try (var statement = connection.prepareStatement("select id from users where id=? for update")) {
                statement.setObject(1, user);
                statement.executeQuery().close();
            }
            var future = executor.submit(() -> service.changePassword(user, session, PASSWORD, "another long password"));
            awaitBlockedAccountQuery();
            Thread.sleep(1200);
            connection.commit();
            assertEquals(AccountService.Result.REAUTHENTICATION_REQUIRED, future.get(10, TimeUnit.SECONDS));
            assertEquals(0L, jdbc.queryForObject("select auth_version from users where id=?", Long.class, user));
        } finally { executor.shutdownNow(); }
    }
    private static void awaitBlockedAccountQuery() throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (System.nanoTime() < deadline) {
            Integer blocked = jdbc.queryForObject("select count(*) from pg_stat_activity where datname=current_database() and wait_event_type='Lock' and query like '%for update%'", Integer.class);
            if (blocked != null && blocked > 0) return;
            Thread.sleep(25);
        }
        fail("Account operation did not wait for row lock");
    }
    private static void expirePending() { jdbc.update("update users set registration_expires_at = clock_timestamp() - interval '1 second'"); }
    private static UUID userId() { return jdbc.queryForObject("select id from users", UUID.class); }
    private static int count(String table) { return jdbc.queryForObject("select count(*) from " + table, Integer.class); }
    private static String newestToken(String purpose) throws Exception {
        return jdbc.query("select challenge_id,encrypted_payload from notification_outbox where purpose=? order by created_at desc limit 1", rs -> {
            if (!rs.next()) throw new IllegalStateException("missing outbox message");
            UUID challenge = rs.getObject(1, UUID.class);
            try {
                byte[] plain = cipher.decrypt(rs.getBytes(2), challenge.toString().getBytes(StandardCharsets.US_ASCII));
                try (var data = new DataInputStream(new ByteArrayInputStream(plain))) { assertEquals(EMAIL, data.readUTF()); return data.readUTF(); }
            } catch (Exception e) { throw new IllegalStateException(e); }
        }, purpose);
    }
}
