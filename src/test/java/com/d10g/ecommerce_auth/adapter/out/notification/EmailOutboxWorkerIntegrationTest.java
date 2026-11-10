package com.d10g.ecommerce_auth.adapter.out.notification;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
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
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DB_URL", matches = ".+")
class EmailOutboxWorkerIntegrationTest {
    private static final UUID USER = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID CHALLENGE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID MESSAGE = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static JdbcTemplate admin;
    private static JdbcTemplate db;
    private static String schema;
    private static TransactionTemplate transaction;
    private static final OutboxKeyRing keys = new OutboxKeyRing("current", Map.of("current", Base64.getEncoder().encodeToString(new byte[32])));
    private CaptureMail mail;
    private EmailOutboxWorker worker;

    static class CaptureMail extends JavaMailSenderImpl {
        final List<SimpleMailMessage> messages = new CopyOnWriteArrayList<>();
        volatile boolean fail;
        @Override public void send(SimpleMailMessage message) {
            if (fail) throw new MailSendException("SMTP unavailable");
            messages.add(new SimpleMailMessage(message));
        }
    }

    @BeforeAll static void initialize() {
        String url = System.getenv("AUTH_TEST_DB_URL");
        String user = System.getenv().getOrDefault("AUTH_TEST_DB_USER", "postgres");
        String password = System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD", "");
        admin = new JdbcTemplate(new DriverManagerDataSource(url, user, password));
        schema = "outbox_it_" + UUID.randomUUID().toString().replace("-", "");
        admin.execute("create schema " + schema);
        var ds = new DriverManagerDataSource(url + (url.contains("?") ? "&" : "?") + "currentSchema=" + schema, user, password);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        db = new JdbcTemplate(ds);
        transaction = new TransactionTemplate(new DataSourceTransactionManager(ds));
    }
    @AfterAll static void cleanup() { if (admin != null && schema != null) admin.execute("drop schema " + schema + " cascade"); }
    @BeforeEach void seed() throws Exception {
        db.execute("truncate notification_outbox, auth_challenges, users cascade");
        db.update("insert into users(id,username,email,password_hash,email_verified,status,registration_expires_at,auth_version,created_at,updated_at) values (?, 'alice','alice@example.test','hash',false,'PENDING_VERIFICATION',clock_timestamp()+interval '1 day',0,clock_timestamp(),clock_timestamp())", USER);
        db.update("insert into auth_challenges(id,purpose,user_id,token_hash,auth_version,expires_at,created_at) values (?,'VERIFY_EMAIL',?,'hash',0,clock_timestamp()+interval '1 hour',clock_timestamp())", CHALLENGE, USER);
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (DataOutputStream data = new DataOutputStream(bytes)) { data.writeUTF("alice@example.test"); data.writeUTF("secret_token"); }
        byte[] encrypted = keys.activeCipher().encrypt(bytes.toByteArray(), CHALLENGE.toString().getBytes(StandardCharsets.US_ASCII));
        db.update("insert into notification_outbox(id,challenge_id,purpose,generation,encrypted_payload,key_id,expires_at,status,attempts,next_attempt_at,created_at) values (?,?,'VERIFY_EMAIL',1,?,'current',clock_timestamp()+interval '1 hour','PENDING',0,clock_timestamp(),clock_timestamp())", MESSAGE, CHALLENGE, encrypted);
        mail = new CaptureMail();
        var sender = new EmailNotificationSender(mail, "sender@example.test", "https://example.test/verify", "https://example.test/reset");
        worker = new EmailOutboxWorker(db, transaction, keys, sender, 20, 3, Duration.ofSeconds(1));
    }

    @Test void sendsAndDeletesSecret() {
        assertEquals(1, worker.runOnce());
        assertEquals(1, mail.messages.size());
        assertTrue(mail.messages.get(0).getText().contains("#token=secret_token"));
        assertEquals("SENT", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertNull(db.queryForObject("select encrypted_payload from notification_outbox where id=?", byte[].class, MESSAGE));
        assertEquals(0, worker.runOnce());
    }

    @Test void rejectsSupersededChallengeWithoutSending() {
        db.update("update auth_challenges set superseded_at=clock_timestamp() where id=?", CHALLENGE);
        worker.runOnce();
        assertEquals("EXPIRED", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertTrue(mail.messages.isEmpty());
        assertNull(db.queryForObject("select encrypted_payload from notification_outbox where id=?", byte[].class, MESSAGE));
    }

    @Test void rejectsExpiredChallengeAndMismatchedGeneration() {
        db.update("update auth_challenges set generation=2 where id=?", CHALLENGE);
        worker.runOnce();
        assertEquals("EXPIRED", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertTrue(mail.messages.isEmpty());
        db.update("update auth_challenges set generation=1, expires_at=clock_timestamp()-interval '1 second' where id=?", CHALLENGE);
        db.update("update notification_outbox set status='PENDING', encrypted_payload=? where id=?", new byte[]{1}, MESSAGE);
        worker.runOnce();
        assertEquals("EXPIRED", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertTrue(mail.messages.isEmpty());
    }

    @Test void deletesPayloadAfterRetryLimit() {
        mail.fail = true;
        for (int i = 0; i < 3; i++) {
            db.update("update notification_outbox set next_attempt_at=clock_timestamp() where id=?", MESSAGE);
            worker.runOnce();
        }
        assertEquals("FAILED", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertNull(db.queryForObject("select encrypted_payload from notification_outbox where id=?", byte[].class, MESSAGE));
        assertEquals(3, db.queryForObject("select attempts from notification_outbox where id=?", Integer.class, MESSAGE));
    }

    @Test void failedDeliveryRetriesOriginalPayload() {
        mail.fail = true;
        worker.runOnce();
        assertEquals("PENDING", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertEquals(1, db.queryForObject("select attempts from notification_outbox where id=?", Integer.class, MESSAGE));
        assertNotNull(db.queryForObject("select encrypted_payload from notification_outbox where id=?", byte[].class, MESSAGE));
        db.update("update notification_outbox set next_attempt_at=clock_timestamp() where id=?", MESSAGE);
        mail.fail = false;
        worker.runOnce();
        assertEquals("SENT", db.queryForObject("select status from notification_outbox where id=?", String.class, MESSAGE));
        assertTrue(mail.messages.get(0).getText().contains("secret_token"));
    }

    @Test void workersDoNotSendSameMessageConcurrently() throws Exception {
        var pool = Executors.newFixedThreadPool(2);
        var start = new CountDownLatch(1);
        try {
            var a = pool.submit(() -> { start.await(); return worker.runOnce(); });
            var b = pool.submit(() -> { start.await(); return worker.runOnce(); });
            start.countDown();
            assertEquals(1, a.get(10, TimeUnit.SECONDS) + b.get(10, TimeUnit.SECONDS));
            assertEquals(1, mail.messages.size());
        } finally { pool.shutdownNow(); }
    }
}
