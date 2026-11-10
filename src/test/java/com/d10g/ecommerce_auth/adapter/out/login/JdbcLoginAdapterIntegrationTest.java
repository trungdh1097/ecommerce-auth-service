package com.d10g.ecommerce_auth.adapter.out.login;

import static com.d10g.ecommerce_auth.application.session.SessionPorts.*;
import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionIssuer;
import com.d10g.ecommerce_auth.application.login.LoginService;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import com.d10g.ecommerce_auth.security.crypto.OutboxCipher;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
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

@EnabledIfEnvironmentVariable(named="AUTH_TEST_DB_URL",matches=".+")
class JdbcLoginAdapterIntegrationTest {
    private static JdbcTemplate admin, db;
    private static String schema;
    private static LoginService login, failingLogin;
    private static OutboxCipher cipher;
    private static final OpaqueSecrets SECRETS = new OpaqueSecrets();
    private static final UUID USER = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID OTHER = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID CONTEXT = UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final byte[] CONTEXT_HASH = SECRETS.sha256("context-secret");
    private static final Client WEB = new Client("web",Platform.WEB,CONTEXT_HASH);
    private static final Client NATIVE = new Client("android",Platform.ANDROID,null);
    @BeforeAll static void setup() {
        String url=System.getenv("AUTH_TEST_DB_URL");
        String user=System.getenv().getOrDefault("AUTH_TEST_DB_USER","postgres");
        String password=System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD","");
        admin=new JdbcTemplate(new DriverManagerDataSource(url,user,password));
        schema="auth_login_"+UUID.randomUUID().toString().replace("-","");
        admin.execute("create schema "+schema);
        var ds=new DriverManagerDataSource(url+(url.contains("?")?"&":"?")+"currentSchema="+schema,user,password);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        db=new JdbcTemplate(ds);
        PasswordEncoder encoder = new PasswordEncoder() {
            public String encode(CharSequence value) { return "test:"+value; }
            public boolean matches(CharSequence value,String encoded) { return encoded.equals(encode(value)); }
        };
        var crypto=new LoginCrypto(encoder,SECRETS,new byte[32]);
        cipher=new OutboxCipher(new byte[32]);
        AccessTokens tokens=new AccessTokens() {
            public String sign(ActiveSession s,Instant issued,Instant expiry) { return "signed"; }
            public VerifiedAccessToken verify(String token) { return null; }
        };
        LoginRateLimits limits=new LoginRateLimits() {
            public void checkPassword(String u,String ip) {} public void passwordFailure() {} public void passwordSuccess() {}
            public void checkOtp(UUID u,UUID c) {} public void otpFailure() {} public void otpSuccess() {} public void checkMail(UUID u) {}
        };
        var issuer=new JdbcSessionIssuer(db,SECRETS,tokens);
        var adapter=new JdbcLoginAdapter(db,new TransactionTemplate(new DataSourceTransactionManager(ds)),crypto,SECRETS,cipher,"test",issuer,limits);
        login=new LoginService(adapter);
        AccessTokens failingTokens=new AccessTokens() {
            public String sign(ActiveSession s,Instant issued,Instant expiry) { throw new IllegalStateException("signing failed"); }
            public VerifiedAccessToken verify(String token) { return null; }
        };
        var failingIssuer=new JdbcSessionIssuer(db,SECRETS,failingTokens);
        failingLogin=new LoginService(new JdbcLoginAdapter(db,new TransactionTemplate(new DataSourceTransactionManager(ds)),crypto,SECRETS,cipher,"test",failingIssuer,limits));
    }
    @AfterAll static void cleanup() { if(admin!=null && schema!=null) admin.execute("drop schema "+schema+" cascade"); }
    @BeforeEach void seed() {
        db.execute("truncate notification_outbox,auth_challenges,refresh_tokens,sessions,browser_contexts,external_identities,audit_events,users cascade");
        Timestamp now=Timestamp.from(Instant.now());
        for (UUID id : new UUID[]{USER,OTHER}) {
            String name=id.equals(USER)?"alice":"other";
            db.update("insert into users(id,username,email,password_hash,email_verified,status,auth_version,created_at,updated_at) values (?,?,?,?,true,'ACTIVE',0,?,?)",id,name,name+"@example.test","test:password",now,now);
        }
        db.update("insert into browser_contexts(id,secret_hash,created_at,last_seen_at) values (?,?,?,?)",CONTEXT,CONTEXT_HASH,now,now);
    }
    @Test void otpMustMatchBindingAndIsConsumedOnce() throws Exception {
        var first=login.login("alice","password",NATIVE,"127.0.0.1");
        assertEquals(LoginService.Status.ACCEPTED,first.status());
        String otp=readOtp(first.challengeId());
        assertEquals(LoginService.Status.CHALLENGE_INVALID,login.verify(first.challengeId(),NATIVE,"different",otp).status());
        assertEquals(LoginService.Status.CHALLENGE_INVALID,login.verify(first.challengeId(),new Client("android",Platform.IOS,null),first.nativeBinding(),otp).status());
        assertEquals(LoginService.Status.OTP_INVALID,login.verify(first.challengeId(),NATIVE,first.nativeBinding(),wrong(otp)).status());
        var result=login.verify(first.challengeId(),NATIVE,first.nativeBinding(),otp);
        assertEquals(LoginService.Status.SUCCESS,result.status());
        assertEquals(LoginService.Status.CHALLENGE_INVALID,login.verify(first.challengeId(),NATIVE,first.nativeBinding(),otp).status());
        assertEquals(1,db.queryForObject("select count(*) from sessions where status='ACTIVE'",Integer.class));
        assertEquals(1,db.queryForObject("select attempts from auth_challenges where id=?",Integer.class,first.challengeId()));
        assertEquals(1,db.queryForObject("select count(*) from audit_events where event_type='LOGIN_FAILURE' and user_id=?",Integer.class,USER));
        assertEquals(1,db.queryForObject("select count(*) from audit_events where event_type='LOGIN_SUCCESS' and user_id=?",Integer.class,USER));
    }
    @Test void webLoginReplacesContextAndTargetWebButKeepsMobile() throws Exception {
        Instant now=Instant.now();
        UUID otherWeb=UUID.randomUUID(), oldWeb=UUID.randomUUID(), mobile=UUID.randomUUID(), otherContext=UUID.randomUUID();
        db.update("insert into browser_contexts(id,secret_hash,created_at,last_seen_at) values (?,?,?,?)",otherContext,SECRETS.sha256("other-context"),Timestamp.from(now),Timestamp.from(now));
        seedSession(otherWeb,OTHER,"web","WEB",CONTEXT,now);
        seedSession(oldWeb,USER,"web","WEB",otherContext,now);
        seedSession(mobile,USER,"android","ANDROID",null,now);
        var challenge=login.login("alice","password",WEB,"127.0.0.1");
        assertEquals("ACTIVE",status(otherWeb));
        assertEquals("ACTIVE",status(oldWeb));
        var result=login.verify(challenge.challengeId(),WEB,null,readOtp(challenge.challengeId()));
        assertEquals(LoginService.Status.SUCCESS,result.status());
        assertEquals("REVOKED",status(otherWeb)); assertEquals("REVOKED",status(oldWeb)); assertEquals("ACTIVE",status(mobile));
        assertEquals(1,db.queryForObject("select count(*) from sessions where user_id=? and platform='WEB' and status='ACTIVE'",Integer.class,USER));
        assertEquals(2,db.queryForObject("select count(*) from audit_events where event_type='SESSION_REPLACED'",Integer.class));
    }
    @Test void verifiedNativeDeviceRequiresBothIdAndSecretAndExpires() throws Exception {
        var challenge=login.login("alice","password",NATIVE,"127.0.0.1","installation-1",null);
        var verified=login.verify(challenge.challengeId(),NATIVE,challenge.nativeBinding(),readOtp(challenge.challengeId()));
        assertNotNull(verified.deviceSecret());
        assertEquals(LoginService.Status.SUCCESS,login.login("alice","password",NATIVE,"127.0.0.1","installation-1",verified.deviceSecret()).status());
        assertEquals("pwd",db.queryForObject("select amr from sessions where user_id=? and status='ACTIVE'",String.class,USER));
        assertEquals(LoginService.Status.ACCEPTED,login.login("alice","password",NATIVE,"127.0.0.1","installation-2",verified.deviceSecret()).status());
        assertEquals(LoginService.Status.ACCEPTED,login.login("alice","password",NATIVE,"127.0.0.1","installation-1","wrong-secret").status());
        db.update("update trusted_devices set expires_at=? where user_id=?",Timestamp.from(Instant.now().minusSeconds(1)),USER);
        assertEquals(LoginService.Status.ACCEPTED,login.login("alice","password",NATIVE,"127.0.0.1","installation-1",verified.deviceSecret()).status());
    }

    @Test void signingFailureRollsBackChallengeAndDeviceTrust() throws Exception {
        var challenge=login.login("alice","password",NATIVE,"127.0.0.1","installation-1",null);
        String otp=readOtp(challenge.challengeId());
        assertThrows(IllegalStateException.class,
                () -> failingLogin.verify(challenge.challengeId(),NATIVE,challenge.nativeBinding(),otp));
        assertEquals(0,db.queryForObject("select count(*) from trusted_devices where user_id=?",Integer.class,USER));
        assertEquals(0,db.queryForObject("select count(*) from sessions where user_id=?",Integer.class,USER));
        assertNull(db.queryForObject("select consumed_at from auth_challenges where id=?",Timestamp.class,challenge.challengeId()));
        assertEquals(LoginService.Status.SUCCESS,login.verify(challenge.challengeId(),NATIVE,challenge.nativeBinding(),otp).status());
    }

    @Test void webContextTrustIsUserScopedAndInvalidatedByAuthVersion() throws Exception {
        var challenge=login.login("alice","password",WEB,"127.0.0.1");
        login.verify(challenge.challengeId(),WEB,null,readOtp(challenge.challengeId()));
        assertEquals(LoginService.Status.SUCCESS,login.login("alice","password",WEB,"127.0.0.1").status());
        assertEquals(LoginService.Status.ACCEPTED,login.login("other","password",WEB,"127.0.0.1").status());
        db.update("update users set auth_version=auth_version+1 where id=?",USER);
        assertEquals(LoginService.Status.ACCEPTED,login.login("alice","password",WEB,"127.0.0.1").status());
    }

    @Test void trustedWebLoginReplacesCurrentContextSessionAndKeepsMobile() throws Exception {
        var aliceChallenge=login.login("alice","password",WEB,"127.0.0.1");
        login.verify(aliceChallenge.challengeId(),WEB,null,readOtp(aliceChallenge.challengeId()));
        var otherChallenge=login.login("other","password",WEB,"127.0.0.1");
        var otherSession=login.verify(otherChallenge.challengeId(),WEB,null,readOtp(otherChallenge.challengeId())).tokens().sessionId();
        UUID mobile=UUID.randomUUID();
        seedSession(mobile,USER,"android","ANDROID",null,Instant.now());
        var result=login.login("alice","password",WEB,"127.0.0.1");
        assertEquals(LoginService.Status.SUCCESS,result.status());
        assertEquals("REVOKED",status(otherSession));
        assertEquals("ACTIVE",status(mobile));
        assertEquals(1,db.queryForObject("select count(*) from sessions where browser_context_id=? and status='ACTIVE'",Integer.class,CONTEXT));
    }
    @Test void simultaneousOtpVerificationConsumesOnce() throws Exception {
        var challenge=login.login("alice","password",NATIVE,"127.0.0.1");
        String otp=readOtp(challenge.challengeId());
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        var start=new java.util.concurrent.CountDownLatch(1);
        try {
            var a=pool.submit(() -> { start.await(); return login.verify(challenge.challengeId(),NATIVE,challenge.nativeBinding(),otp).status(); });
            var b=pool.submit(() -> { start.await(); return login.verify(challenge.challengeId(),NATIVE,challenge.nativeBinding(),otp).status(); });
            start.countDown();
            assertEquals(java.util.Set.of(LoginService.Status.SUCCESS,LoginService.Status.CHALLENGE_INVALID),
                    java.util.Set.of(a.get(10,java.util.concurrent.TimeUnit.SECONDS), b.get(10,java.util.concurrent.TimeUnit.SECONDS)));
            assertEquals(1,db.queryForObject("select count(*) from sessions where user_id=? and status='ACTIVE'",Integer.class,USER));
        } finally { pool.shutdownNow(); }
    }
    private String readOtp(UUID id) throws Exception {
        byte[] payload=db.queryForObject("select encrypted_payload from notification_outbox where challenge_id=? order by created_at desc limit 1",byte[].class,id);
        byte[] plain=cipher.decrypt(payload,id.toString().getBytes(StandardCharsets.US_ASCII));
        try(var in=new DataInputStream(new ByteArrayInputStream(plain))) { in.readUTF(); return in.readUTF(); }
    }
    private static String wrong(String otp) { return otp.equals("000000")?"000001":"000000"; }
    private void seedSession(UUID id, UUID user,String client,String platform,UUID context,Instant now) {
        Timestamp t=Timestamp.from(now);
        db.update("insert into sessions(id,user_id,client_id,platform,browser_context_id,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at) values (?,?,?,?,?,'ACTIVE',0,?,'pwd otp',?,?,?,?)",id,user,client,platform,context,t,t,t,t,Timestamp.from(now.plusSeconds(3600)));
    }
    private String status(UUID id) { return db.queryForObject("select status from sessions where id=?",String.class,id); }
}
