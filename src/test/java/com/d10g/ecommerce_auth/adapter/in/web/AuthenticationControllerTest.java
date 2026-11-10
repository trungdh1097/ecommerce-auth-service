package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import com.d10g.ecommerce_auth.adapter.out.login.RedisPublicLimits;
import com.d10g.ecommerce_auth.application.account.AccountService;
import com.d10g.ecommerce_auth.application.login.LoginPorts;
import com.d10g.ecommerce_auth.application.login.LoginService;
import com.d10g.ecommerce_auth.application.session.SessionPorts;
import com.d10g.ecommerce_auth.application.session.SessionService;
import com.d10g.ecommerce_auth.domain.account.Account;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class AuthenticationControllerTest {
    private static final Instant NOW=Instant.parse("2026-01-01T00:00:00Z");
    private final UUID sessionId=UUID.randomUUID(), userId=UUID.randomUUID();
    private final FakeLogin login=new FakeLogin();
    private final FakeSessions sessions=new FakeSessions();
    private final StringRedisTemplate redis=new StringRedisTemplate() {
        @Override @SuppressWarnings("unchecked") public <T> T execute(RedisScript<T> script,List<String> keys,Object... args) { return (T) Long.valueOf(1); }
    };
    private final OpaqueSecrets secrets=new OpaqueSecrets();
    private final WebAuthSupport support=new WebAuthSupport(new ClientRegistry(Map.of(
            "android",new ClientRegistry.Registration(SessionPorts.Platform.ANDROID,"aud",Set.of()),
            "web",new ClientRegistry.Registration(SessionPorts.Platform.WEB,"aud",Set.of())),Set.of("https://shop.test")),
            secrets,new JdbcTemplate(),new RedisPublicLimits(redis,secrets));
    private final SessionPorts.Transaction transaction=new SessionPorts.Transaction() { public <T> T execute(Supplier<T> work) { return work.get(); } };
    private final SessionPorts.Secrets tokenSecrets=new SessionPorts.Secrets() {
        public String newRefreshToken() { return "rotated"; }
        public byte[] hash(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    };
    private final SessionPorts.AccessTokens accessTokens=new SessionPorts.AccessTokens() {
        public String sign(SessionPorts.ActiveSession session,Instant issued,Instant expiry) { return "new-access"; }
        public SessionPorts.VerifiedAccessToken verify(String token) { return null; }
    };
    private final SessionService sessionService=new SessionService(transaction,sessions,tokenSecrets,accessTokens,Clock.fixed(NOW,ZoneOffset.UTC));
    private final AuthenticationController controller=new AuthenticationController(new AccountService(null),new LoginService(login),sessionService,support);
    private final org.springframework.test.web.servlet.MockMvc mvc=MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ApiProblemHandler()).build();

    @Test void nativeLoginOtpThenRefreshAndLogoutUseCorrectWireFormat() throws Exception {
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"username\":\"alice\",\"password\":\"correct\"}"))
                .andExpect(status().isAccepted()).andExpect(jsonPath("$.continuation_secret").value("binding"))
                .andExpect(jsonPath("$.access_token").doesNotExist());
        assertNotNull(login.created);
        mvc.perform(post("/api/v1/auth/login/otp/verify").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"challenge_id\":\""+login.created.id()+"\",\"continuation_secret\":\"binding\",\"otp\":\"123456\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").value("refresh"))
                .andExpect(jsonPath("$.access_token").value("access")).andExpect(header().doesNotExist("Set-Cookie"));
        mvc.perform(post("/api/v1/auth/refresh").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"expected_session_id\":\""+sessionId+"\",\"refresh_token\":\"old\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.refresh_token").value("rotated"));
        mvc.perform(post("/api/v1/auth/logout").header("X-Client-Id","android").header("Authorization","Bearer expired").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"expected_session_id\":\""+sessionId+"\",\"refresh_token\":\"old\"}"))
                .andExpect(status().isNoContent());
        assertTrue(sessions.revoked);
    }
    @Test void rememberedNativeDeviceGetsTokensAtLogin() throws Exception {
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"username\":\"alice\",\"password\":\"correct\",\"device_id\":\"phone\"}"))
                .andExpect(status().isAccepted());
        mvc.perform(post("/api/v1/auth/login/otp/verify").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"challenge_id\":\""+login.created.id()+"\",\"continuation_secret\":\"binding\",\"otp\":\"123456\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.device_secret").value("trusted-secret"));
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"username\":\"alice\",\"password\":\"correct\",\"device_id\":\"phone\",\"device_secret\":\"trusted-secret\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.access_token").value("access"))
                .andExpect(jsonPath("$.refresh_token").value("refresh")).andExpect(jsonPath("$.device_secret").doesNotExist());
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"username\":\"alice\",\"password\":\"correct\",\"device_id\":\"phone\",\"device_secret\":\"trusted-secret\",\"require_otp\":true}"))
                .andExpect(status().isAccepted()).andExpect(jsonPath("$.challenge_id").exists());
    }
    @Test void staleExpectedSessionReturnsConflictWithoutCookieOrMutation() throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").header("X-Client-Id","android").contentType(MediaType.APPLICATION_JSON)
                .content("{\"client_id\":\"android\",\"expected_session_id\":\""+UUID.randomUUID()+"\",\"refresh_token\":\"old\"}"))
                .andExpect(status().isConflict()).andExpect(jsonPath("$.code").value("SESSION_CONTEXT_CHANGED"))
                .andExpect(header().doesNotExist("Set-Cookie"));
        assertFalse(sessions.rotated || sessions.revoked);
    }
    private final class FakeLogin implements LoginPorts {
        private final User user=new User(userId,"alice","alice@example.test","hash",0,Account.Status.ACTIVE,true);
        private Challenge created;
        private String pendingDeviceId, trustedDeviceId;
        public <T>T inTransaction(Supplier<T> work){return work.get();}
        public User findUser(String name){return user;}
        public User lockUserForLogin(UUID id,SessionPorts.Client client){return user;}
        public Challenge lockChallenge(UUID id,SessionPorts.Client client,String binding){return created!=null && id.equals(created.id()) && "binding".equals(binding)?created:null;}
        public Instant now(){return NOW;}
        public boolean passwordMatches(String pass,String hash){return "correct".equals(pass);}
        public String dummyPasswordHash(){return "dummy";}
        public String newNativeBinding(){return "binding";}
        public String newOtp(){return "123456";}
        public byte[] otpMac(UUID id,int generation,String otp){return (id+":"+generation+":"+otp).getBytes(StandardCharsets.UTF_8);}
        public boolean constantTimeEquals(byte[] a,byte[] b){return Arrays.equals(a,b);}
        public void createChallenge(UUID id,User user,SessionPorts.Client client,String binding,byte[] mac,Instant now,Instant expires,String deviceId){pendingDeviceId=deviceId;created=new Challenge(id,user,client.clientId(),0,mac,1,0,expires,now,false,false);}
        public boolean isTrusted(User user,SessionPorts.Client client,String deviceId,String deviceSecret,Instant now){return trustedDeviceId != null && trustedDeviceId.equals(deviceId) && "trusted-secret".equals(deviceSecret);}
        public Tokens completeTrusted(User user,SessionPorts.Client client,Instant now){return new Tokens("access","refresh",sessionId,300);}
        public String rememberDevice(Challenge c,SessionPorts.Client client,Instant now,Instant expiry){trustedDeviceId=pendingDeviceId;return trustedDeviceId == null ? null : "trusted-secret";}
        public void enqueueOtp(Challenge c,String otp,Instant now){}
        public void incrementAttempts(Challenge challenge){}
        public void resendOtp(Challenge c,byte[] mac,Instant now,Instant expires){}
        public Tokens complete(Challenge c,SessionPorts.Client client,Instant now){return new Tokens("access","refresh",sessionId,300);}
        public void checkPasswordLimit(String username,String ip){} public void recordPasswordFailure(String username,String ip){}
        public void checkOtpLimit(UUID userId,UUID id){} public void recordOtpFailure(UUID userId,UUID id){} public void checkMailLimit(UUID userId){}
    }
    private final class FakeSessions implements SessionPorts.Store {
        boolean rotated,revoked;
        public SessionPorts.LockedCredential lockCredential(byte[] hash,SessionPorts.Client client){
            if(!Arrays.equals(hash,"old".getBytes(StandardCharsets.UTF_8))) return null;
            var session=new SessionPorts.ActiveSession(userId,sessionId,"android",SessionPorts.Platform.ANDROID,0,NOW,"pwd otp",NOW.plusSeconds(86400),NOW,true,true,0);
            return new SessionPorts.LockedCredential(session,UUID.randomUUID(),UUID.randomUUID(),NOW.plusSeconds(86400),null,null);
        }
        public void rotate(SessionPorts.LockedCredential c,UUID id,byte[] hash,Instant now){rotated=true;}
        public void revoke(SessionPorts.LockedCredential c,Instant now,String reason){revoked=true;}
        public SessionPorts.ActiveSession findActive(UUID userId,UUID sessionId){return null;}
    }
}
