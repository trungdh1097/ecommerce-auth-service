package com.d10g.ecommerce_auth.adapter.in.web;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.mockito.Mockito.mock;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.account.AccountPorts;
import com.d10g.ecommerce_auth.application.role.RolePort;
import com.d10g.ecommerce_auth.application.role.RoleService;
import com.d10g.ecommerce_auth.application.session.SessionPorts;
import com.d10g.ecommerce_auth.application.session.SessionService;
import com.d10g.ecommerce_auth.configuration.SecurityConfiguration;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Exercises the actual filter chain, not only the individual client registry. */
@WebMvcTest(controllers = HttpSecurityIntegrationTest.Endpoints.class)
@Import({SecurityConfiguration.class, HttpSecurityIntegrationTest.Config.class, HttpSecurityIntegrationTest.Endpoints.class})
class HttpSecurityIntegrationTest {
    static final UUID USER=UUID.randomUUID(), SESSION=UUID.randomUUID();
    static final String ORIGIN="https://shop.example.test";
    @Autowired MockMvc mvc;
    @Autowired RsaAccessTokens jwt;
    @Autowired FakeStore store;
    @Autowired FakeRoles roles;

    @AfterEach void reset() {
        store.unavailable.set(false);
        store.active.set(true);
        roles.admin.set(false);
        roles.unavailable.set(false);
    }

    @Test void webMutationsRequireExactOriginAndCsrf() throws Exception {
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","web").header("Origin",ORIGIN))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("CSRF_INVALID"));
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","web").header("Origin","https://evil.test").with(csrf()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","web").header("Origin",ORIGIN).with(csrf()))
                .andExpect(status().isNoContent());
    }

    @Test void nativeMutationsCannotCarryCookiesOrBrowserOrigin() throws Exception {
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android"))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").header("Cookie","refresh=secret"))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/auth/login").header("X-Client-Id","android").header("Origin",ORIGIN))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
    }

    @Test void protectedEndpointsDistinguishInvalidCredentialsAndDependencyOutage() throws Exception {
        mvc.perform(get("/api/v1/auth/me")).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer invalid"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        String token=jwt.sign(store.activeSession(),Instant.now(),Instant.now().plusSeconds(300));
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+token)).andExpect(status().isOk());
        store.active.set(false);
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+token)).andExpect(status().isUnauthorized());
        store.unavailable.set(true);
        mvc.perform(get("/api/v1/auth/me").header("Authorization","Bearer "+token))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("DEPENDENCY_UNAVAILABLE"));
    }

    @Test void roleEndpointsRequireAValidSessionAndCurrentAdminRole() throws Exception {
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer invalid"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        String token=accessToken();
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        roles.admin.set(true);
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/role/review").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isNoContent());
        roles.admin.set(false);
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test void revokedAndExpiredSessionsCannotChangeRolesAndOutagesRemainDistinct() throws Exception {
        roles.admin.set(true);
        String token=accessToken();
        store.active.set(false);
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        store.active.set(true);
        Instant now=Instant.now();
        String expired=jwt.sign(store.activeSession(),now.minusSeconds(600),now.minusSeconds(300));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+expired))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SESSION_REVOKED"));
        store.unavailable.set(true);
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("DEPENDENCY_UNAVAILABLE"));
    }

    @Test void roleLookupOutageDoesNotBecomeAnAuthorizationDenial() throws Exception {
        roles.unavailable.set(true);
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Authorization","Bearer "+accessToken()))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("DEPENDENCY_UNAVAILABLE"));
    }

    @Test void nativeRoleMutationsRequireRegisteredClientWithoutBrowserCredentials() throws Exception {
        roles.admin.set(true);
        String token=accessToken();
        mvc.perform(post("/api/v1/role/change").header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","unknown").header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Cookie","XSRF-TOKEN=secret")
                        .header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","android").header("Origin",ORIGIN)
                        .header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
    }

    @Test void webRoleMutationsRequireExactOriginAndCsrfEvenWithAdminToken() throws Exception {
        roles.admin.set(true);
        String token=accessToken();
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","web").header("Authorization","Bearer "+token).with(csrf()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","web").header("Origin","https://evil.test")
                        .header("Authorization","Bearer "+token).with(csrf()))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("INVALID_CLIENT"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","web").header("Origin",ORIGIN)
                        .header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("CSRF_INVALID"));
        mvc.perform(post("/api/v1/role/change").header("X-Client-Id","web").header("Origin",ORIGIN)
                        .header("Authorization","Bearer "+token).with(csrf()))
                .andExpect(status().isNoContent());
    }

    @Test void roleWildcardDoesNotOpenNestedOrUnrelatedRoutes() throws Exception {
        roles.admin.set(true);
        String token=accessToken();
        mvc.perform(post("/api/v1/role/change/nested").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
        mvc.perform(post("/api/v1/other/change").header("X-Client-Id","android").header("Authorization","Bearer "+token))
                .andExpect(status().isUnauthorized());
    }

    private String accessToken() {
        Instant now=Instant.now();
        return jwt.sign(store.activeSession(),now,now.plusSeconds(300));
    }

    @RestController static class Endpoints {
        @PostMapping("/api/v1/auth/login") ResponseEntity<Void> login() { return ResponseEntity.noContent().build(); }
        @GetMapping("/api/v1/auth/me") ResponseEntity<Void> me() { return ResponseEntity.ok().build(); }
        @PostMapping({"/api/v1/role/change", "/api/v1/role/review", "/api/v1/role/change/nested", "/api/v1/other/change"})
        ResponseEntity<Void> changeRole() { return ResponseEntity.noContent().build(); }
    }
    @TestConfiguration static class Config {
        @Bean ClientRegistry registry() {
            return new ClientRegistry(Map.of("web",new ClientRegistry.Registration(SessionPorts.Platform.WEB,null,Set.of()),
                    "android",new ClientRegistry.Registration(SessionPorts.Platform.ANDROID,null,Set.of())), Set.of(ORIGIN));
        }
        @Bean RsaAccessTokens tokens() throws Exception {
            var generator=KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); var key=generator.generateKeyPair();
            return new RsaAccessTokens("test-issuer","test-audience","test-key",(RSAPrivateKey)key.getPrivate(),
                    Map.of("test-key",(RSAPublicKey)key.getPublic()),Clock.systemUTC());
        }
        @Bean FakeStore fakeStore() { return new FakeStore(); }
        @Bean FakeRoles fakeRoles() { return new FakeRoles(); }
        @Bean RoleService roleService(FakeRoles roles) { return new RoleService(roles,mock(AccountPorts.class)); }
        @Bean SessionService service(FakeStore store, RsaAccessTokens jwt) {
            SessionPorts.Transaction transaction=new SessionPorts.Transaction(){ public <T> T execute(Supplier<T> work){return work.get();} };
            SessionPorts.Secrets secrets=new SessionPorts.Secrets(){ public String newRefreshToken(){return "unused";} public byte[] hash(String s){return new byte[0];} };
            return new SessionService(transaction,store,secrets,jwt,Clock.systemUTC());
        }
    }
    static class FakeRoles implements RolePort {
        final AtomicBoolean admin=new AtomicBoolean(), unavailable=new AtomicBoolean();
        public boolean hasRole(UUID userId,String roleName) {
            if (unavailable.get()) throw new DataAccessResourceFailureException("role database unavailable");
            return USER.equals(userId)&&"ADMIN".equals(roleName)&&admin.get();
        }
        public <T> T inTransaction(Supplier<T> work) { return work.get(); }
        public Optional<Role> findById(int roleId) { throw new UnsupportedOperationException(); }
        public void changeRole(UUID userId,int roleId) { throw new UnsupportedOperationException(); }
    }
    static class FakeStore implements SessionPorts.Store {
        final AtomicBoolean unavailable=new AtomicBoolean(), active=new AtomicBoolean(true);
        SessionPorts.ActiveSession activeSession() {
            Instant now=Instant.now();
            return new SessionPorts.ActiveSession(USER,SESSION,"android",SessionPorts.Platform.ANDROID,1,now,"pwd otp",now.plusSeconds(3600),now,active.get(),true,1);
        }
        public SessionPorts.LockedCredential lockCredential(byte[] hash,SessionPorts.Client client){throw new UnsupportedOperationException();}
        public void rotate(SessionPorts.LockedCredential c,UUID id,byte[] hash,Instant now){throw new UnsupportedOperationException();}
        public void revoke(SessionPorts.LockedCredential c,Instant now,String reason){throw new UnsupportedOperationException();}
        public SessionPorts.ActiveSession findActive(UUID userId,UUID sessionId){
            if (unavailable.get()) throw new DataAccessResourceFailureException("database unavailable");
            return userId.equals(USER)&&sessionId.equals(SESSION)?activeSession():null;
        }
    }
}
