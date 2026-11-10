package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.d10g.ecommerce_auth.adapter.out.notification.OutboxKeyRing;
import com.jayway.jsonpath.JsonPath;
import jakarta.servlet.http.Cookie;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.sql.DriverManager;
import java.util.Base64;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.test.web.servlet.MockMvc;

/** Starts the real runtime with ephemeral keys and an isolated PostgreSQL schema. */
@SpringBootTest
@AutoConfigureMockMvc
@EnabledIfEnvironmentVariable(named="AUTH_TEST_DB_URL",matches=".+")
class AuthRuntimeContextIntegrationTest {
    private static final String SCHEMA="auth_runtime_it_"+UUID.randomUUID().toString().replace("-","");
    private static final String URL=System.getenv("AUTH_TEST_DB_URL");
    private static final String USER=System.getenv().getOrDefault("AUTH_TEST_DB_USER","postgres");
    private static final String PASSWORD=System.getenv().getOrDefault("AUTH_TEST_DB_PASSWORD","");
    @Autowired @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping mappings;
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired OutboxKeyRing keys;
    @DynamicPropertySource static void properties(DynamicPropertyRegistry p) throws Exception {
        try(var c=DriverManager.getConnection(URL,USER,PASSWORD);var s=c.createStatement()) { s.execute("CREATE SCHEMA "+SCHEMA); }
        KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); KeyPair pair=generator.generateKeyPair();
        String sep=URL.contains("?")?"&":"?";
        p.add("spring.datasource.url",()->URL+sep+"currentSchema="+SCHEMA);
        p.add("spring.datasource.username",()->USER); p.add("spring.datasource.password",()->PASSWORD);
        p.add("spring.flyway.schemas",()->SCHEMA);
        p.add("auth.runtime.enabled",()->"true");
        p.add("auth.runtime.otp-hmac-key",()->Base64.getEncoder().encodeToString(new byte[32]));
        p.add("auth.runtime.allowed-origins[0]",()->"https://shop.test");
        p.add("auth.runtime.clients.web.platform",()->"WEB");
        p.add("auth.runtime.clients.web.google-audience",()->"google-web");
        p.add("auth.runtime.clients.web.google-presenters[0]",()->"google-web");
        p.add("auth.runtime.clients.android.platform",()->"ANDROID");
        p.add("auth.runtime.clients.android.google-audience",()->"google-android");
        p.add("auth.runtime.clients.android.google-presenters[0]",()->"google-android");
        p.add("auth.jwt.issuer",()->"https://issuer.test"); p.add("auth.jwt.audience",()->"ecommerce");
        p.add("auth.jwt.active-key-id",()->"test");
        p.add("auth.jwt.private-key-pem",()->Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        p.add("auth.jwt.public-keys.test",()->Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        p.add("auth.outbox.active-key-id",()->"test");
        p.add("auth.outbox.keys.test",()->Base64.getEncoder().encodeToString(new byte[32]));
        p.add("auth.outbox.enabled",()->"true");
        p.add("auth.outbox.from",()->"auth@example.test");
        p.add("auth.outbox.verify-url",()->"https://shop.test/verify");
        p.add("auth.outbox.reset-url",()->"https://shop.test/reset");
        p.add("auth.outbox.poll-interval",()->"PT1H");
        p.add("auth.cleanup.enabled",()->"false");
        if (System.getenv("AUTH_TEST_REDIS_PORT") != null)
            p.add("spring.data.redis.port",()->System.getenv("AUTH_TEST_REDIS_PORT"));
    }
    @AfterAll static void cleanup() throws Exception {
        try(var c=DriverManager.getConnection(URL,USER,PASSWORD);var s=c.createStatement()) { s.execute("DROP SCHEMA IF EXISTS "+SCHEMA+" CASCADE"); }
    }
    @Test void runtimeRegistersControllersAndExpectedMappings() {
        Set<String> paths=mappings.getHandlerMethods().keySet().stream().flatMap(info->info.getPatternValues().stream()).collect(Collectors.toSet());
        assertTrue(paths.containsAll(Set.of("/.well-known/jwks.json","/api/v1/auth/csrf","/api/v1/auth/register",
                "/api/v1/auth/login","/api/v1/auth/login/otp/verify","/api/v1/auth/refresh","/api/v1/auth/logout",
                "/api/v1/auth/google/challenge","/api/v1/auth/google/exchange","/api/v1/auth/me","/api/v1/auth/sessions")),paths.toString());
    }
    @Test
    @EnabledIfEnvironmentVariable(named="AUTH_TEST_REDIS_PORT",matches="[0-9]+")
    void nativeRegistrationLoginOtpRefreshAndLogoutWorkThroughRealAdapters() throws Exception {
        String suffix=UUID.randomUUID().toString().replace("-","").substring(0,12);
        String username="test"+suffix,email=username+"@example.test",password="a passphrase 123";
        mvc.perform(post("/api/v1/auth/register").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\""+username+"\",\"email\":\""+email+"\",\"password\":\""+password+"\"}"))
                .andExpect(status().isAccepted());
        String verification=secretFor(email,"VERIFY_EMAIL");
        mvc.perform(post("/api/v1/auth/email/verify").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\""+verification+"\"}")).andExpect(status().isNoContent());
        var login=mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").header("User-Agent","TestAgent/1.0").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"username\":\""+username+"\",\"password\":\""+password+"\",\"device_label\":\"My Phone\"}"))
                .andExpect(status().isAccepted()).andReturn().getResponse().getContentAsString();
        String challenge=JsonPath.read(login,"$.challenge_id"),binding=JsonPath.read(login,"$.continuation_secret");
        String otp=secretFor(email,"LOGIN_OTP");
        var authenticated=mvc.perform(post("/api/v1/auth/login/otp/verify").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"challenge_id\":\""+challenge+"\",\"continuation_secret\":\""+binding+"\",\"otp\":\""+otp+"\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").exists()).andReturn().getResponse().getContentAsString();
        String session=JsonPath.read(authenticated,"$.session_id"),refresh=JsonPath.read(authenticated,"$.refresh_token");
        var stored=jdbc.queryForMap("select device_label,user_agent,masked_ip from sessions where id=?",UUID.fromString(session));
        assertEquals("My Phone",stored.get("device_label")); assertEquals("TestAgent/1.0",stored.get("user_agent"));
        assertEquals("127.0.0.x",stored.get("masked_ip"));
        var rotated=mvc.perform(post("/api/v1/auth/refresh").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"expected_session_id\":\""+session+"\",\"refresh_token\":\""+refresh+"\"}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String rotatedToken=JsonPath.read(rotated,"$.refresh_token");
        mvc.perform(post("/api/v1/auth/logout").header("X-Client-Id","android").header("Authorization","Bearer expired")
                .contentType(MediaType.APPLICATION_JSON).content("{\"client_id\":\"android\",\"expected_session_id\":\""+session+"\",\"refresh_token\":\""+rotatedToken+"\"}"))
                .andExpect(status().isNoContent());
    }
    @Test
    @EnabledIfEnvironmentVariable(named="AUTH_TEST_REDIS_PORT",matches="[0-9]+")
    void webBootstrapCreatesCookiesAndRequiresCsrfForRegistration() throws Exception {
        var bootstrap=mvc.perform(get("/api/v1/auth/csrf").header("X-Client-Id","web"))
                .andExpect(status().isOk()).andReturn().getResponse();
        String token=JsonPath.read(bootstrap.getContentAsString(),"$.token");
        Cookie context=bootstrap.getCookie(WebAuthSupport.CONTEXT_COOKIE),csrf=bootstrap.getCookie("XSRF-TOKEN");
        assertNotNull(context); assertNotNull(csrf);
        String username="web"+UUID.randomUUID().toString().replace("-","").substring(0,12);
        String body="{\"username\":\""+username+"\",\"email\":\""+username+"@example.test\",\"password\":\"a passphrase 123\"}";
        mvc.perform(post("/api/v1/auth/register").header("X-Client-Id","web").header("Origin","https://shop.test")
                .cookie(context,csrf).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/auth/register").header("X-Client-Id","web").header("Origin","https://shop.test")
                .header("X-XSRF-TOKEN",token).cookie(context,csrf).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isAccepted());
    }
    private String secretFor(String email,String purpose) {
        return jdbc.query("select o.challenge_id,o.encrypted_payload from notification_outbox o join auth_challenges c on c.id=o.challenge_id join users u on u.id=c.user_id where u.email=? and o.purpose=? order by o.created_at desc limit 1",rs->{
            if(!rs.next()) throw new IllegalStateException("Missing outbox message");
            UUID challenge=rs.getObject(1,UUID.class);
            try {
                byte[] plaintext=keys.activeCipher().decrypt(rs.getBytes(2),challenge.toString().getBytes(StandardCharsets.US_ASCII));
                try(var in=new DataInputStream(new ByteArrayInputStream(plaintext))) { assertEquals(email,in.readUTF()); return in.readUTF(); }
            } catch(Exception ex) { throw new IllegalStateException(ex); }
        },email,purpose);
    }
}
