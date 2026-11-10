package com.d10g.ecommerce_auth.adapter.out.session;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.application.session.SessionManagementService;
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
import org.springframework.transaction.support.TransactionTemplate;

@EnabledIfEnvironmentVariable(named="AUTH_TEST_DB_URL",matches=".+")
class JdbcSessionManagementIntegrationTest {
    private static JdbcTemplate admin,db;
    private static String schema;
    private static SessionManagementService service;
    private static final UUID ALICE=UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID BOB=UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID WEB=UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID MOBILE=UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final UUID OTHER=UUID.fromString("55555555-5555-4555-8555-555555555555");
    private static final UUID CONTEXT=UUID.fromString("66666666-6666-4666-8666-666666666666");
    @BeforeAll static void setup() {
        String url=System.getenv("AUTH_TEST_DB_URL"),user=System.getenv().getOrDefault("AUTH_TEST_DB_USER","postgres"),password=System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD","");
        admin=new JdbcTemplate(new DriverManagerDataSource(url,user,password));
        schema="auth_sessions_"+UUID.randomUUID().toString().replace("-","");
        admin.execute("create schema "+schema);
        var ds=new DriverManagerDataSource(url+(url.contains("?")?"&":"?")+"currentSchema="+schema,user,password);
        Flyway.configure().dataSource(ds).schemas(schema).load().migrate();
        db=new JdbcTemplate(ds);
        service=new SessionManagementService(new JdbcSessionManagementStore(db,new TransactionTemplate(new DataSourceTransactionManager(ds))));
    }
    @AfterAll static void cleanup() { if(admin!=null&&schema!=null) admin.execute("drop schema "+schema+" cascade"); }
    @BeforeEach void seed() {
        db.execute("truncate notification_outbox,auth_challenges,refresh_tokens,sessions,browser_contexts,external_identities,audit_events,users cascade");
        Instant now=Instant.now(); Timestamp ts=Timestamp.from(now);
        for(UUID id:new UUID[]{ALICE,BOB}) {String name=id.equals(ALICE)?"alice":"bob";db.update("insert into users(id,username,email,password_hash,email_verified,status,auth_version,created_at,updated_at) values (?,?,?,?,true,'ACTIVE',0,?,?)",id,name,name+"@example.test","hash",ts,ts);}
        db.update("insert into browser_contexts(id,secret_hash,created_at,last_seen_at) values (?,?,?,?)",CONTEXT,new byte[]{1},ts,ts);
        seedSession(WEB,ALICE,"WEB",CONTEXT,now);
        seedSession(MOBILE,ALICE,"ANDROID",null,now.minusSeconds(1));
        seedSession(OTHER,BOB,"IOS",null,now);
        db.update("insert into external_identities(id,user_id,provider,provider_subject,created_at,updated_at) values (?,?,'GOOGLE','sub',?,?)",UUID.randomUUID(),ALICE,ts,ts);
    }
    private static void seedSession(UUID id,UUID user,String platform,UUID context,Instant now) {
        Timestamp ts=Timestamp.from(now);
        db.update("insert into sessions(id,user_id,client_id,platform,browser_context_id,status,auth_version,auth_time,amr,created_at,last_seen_at,last_refresh_at,expires_at) values (?,?,'test',?,?,'ACTIVE',0,?,'pwd otp',?,?,?,?)",id,user,platform,context,ts,ts,ts,ts,Timestamp.from(now.plusSeconds(3600)));
        db.update("insert into refresh_tokens(id,session_id,family_id,token_hash,issued_at,expires_at) values (?,?,?,?,?,?)",UUID.randomUUID(),id,UUID.randomUUID(),id.toString().getBytes(),ts,Timestamp.from(now.plusSeconds(3600)));
    }
    @Test void profileAndPaginationAreUserScoped() {
        var me=service.me(ALICE); assertEquals("alice",me.username()); assertEquals(java.util.List.of("PASSWORD","GOOGLE"),me.loginMethods());
        var first=service.sessions(ALICE,WEB,null,1); assertEquals(1,first.sessions().size()); assertTrue(first.sessions().get(0).current()); assertNotNull(first.nextCursor());
        var second=service.sessions(ALICE,WEB,first.nextCursor(),1); assertEquals(MOBILE,second.sessions().get(0).id()); assertFalse(second.sessions().get(0).current()); assertNull(second.nextCursor());
        assertThrows(IllegalArgumentException.class,()->service.sessions(ALICE,WEB,"invalid",20));
    }
    @Test void revokeIsOwnerScopedAndIdempotent() {
        assertEquals(SessionManagementService.RevokeResult.NOT_FOUND,service.revoke(ALICE,OTHER));
        assertEquals("ACTIVE",status(OTHER));
        assertEquals(SessionManagementService.RevokeResult.REVOKED,service.revoke(ALICE,MOBILE));
        assertEquals(SessionManagementService.RevokeResult.REVOKED,service.revoke(ALICE,MOBILE));
        assertEquals("REVOKED",status(MOBILE));
        assertEquals(1,db.queryForObject("select count(*) from refresh_tokens where session_id=? and revoked_at is not null",Integer.class,MOBILE));
        assertEquals("ACTIVE",status(WEB));
        assertEquals(1,db.queryForObject("select count(*) from audit_events where event_type='SESSION_REVOKED' and user_id=?",Integer.class,ALICE));
    }
    @Test void logoutAllRevokesOnlyOwnersSessionsAndAdvancesVersion() {
        service.logoutAll(ALICE);
        assertEquals(1L,db.queryForObject("select auth_version from users where id=?",Long.class,ALICE));
        assertNotNull(db.queryForObject("select revoked_before from users where id=?",Timestamp.class,ALICE));
        assertEquals("REVOKED",status(WEB)); assertEquals("REVOKED",status(MOBILE)); assertEquals("ACTIVE",status(OTHER));
        assertEquals(2,db.queryForObject("select count(*) from refresh_tokens where session_id in (?,?) and revoked_at is not null",Integer.class,WEB,MOBILE));
        assertEquals(1,db.queryForObject("select count(*) from audit_events where event_type='LOGOUT_ALL' and user_id=?",Integer.class,ALICE));
    }
    private String status(UUID session) {return db.queryForObject("select status from sessions where id=?",String.class,session);}
}
