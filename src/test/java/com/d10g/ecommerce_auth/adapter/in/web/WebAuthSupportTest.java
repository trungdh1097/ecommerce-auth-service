package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.adapter.out.login.RedisPublicLimits;
import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import jakarta.servlet.http.Cookie;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

class WebAuthSupportTest {
    private final OpaqueSecrets secrets = new OpaqueSecrets();
    private final ClientRegistry clients = new ClientRegistry(Map.of(
            "web",new ClientRegistry.Registration(Platform.WEB,"aud",Set.of()),
            "android",new ClientRegistry.Registration(Platform.ANDROID,"aud",Set.of())),Set.of("https://example.test"));
    private final JdbcTemplate jdbc = new JdbcTemplate() {
        @Override public <T> T queryForObject(String sql, Class<T> type, Object... args) { return type.cast(Boolean.TRUE); }
    };
    private final WebAuthSupport support = new WebAuthSupport(clients,secrets,jdbc,new RedisPublicLimits(new StringRedisTemplate(),secrets));

    @Test void contextCookiePersistsForConfiguredTrustDuration() {
        String cookie = support.contextCookie("context").toString();
        assertTrue(cookie.contains("Max-Age=7776000"));
        assertTrue(cookie.contains("HttpOnly") && cookie.contains("Secure") && cookie.contains("SameSite=Lax"));
    }
    @Test void otpSuccessRenewsTheExistingWebContextCookie() {
        var request = new MockHttpServletRequest();
        String context = secrets.generate();
        request.setCookies(new Cookie(WebAuthSupport.CONTEXT_COOKIE, context));
        var response = support.tokenResponse(new Client("web",Platform.WEB,new byte[32]),
                new Tokens("access","refresh",UUID.randomUUID(),300), null, request);
        var cookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertEquals(2,cookies.size());
        assertTrue(cookies.stream().anyMatch(value -> value.contains("AUTH_CONTEXT=" + context) && value.contains("Max-Age=7776000")));
    }

    @Test void webRefreshIsOnlyACookieAndNativeRefreshIsInBody() {
        Tokens tokens = new Tokens("access-secret","refresh-secret",UUID.randomUUID(),300);
        var web = support.tokenResponse(new Client("web",Platform.WEB,new byte[32]),tokens);
        assertFalse(web.getBody().containsKey("refresh_token"));
        String cookie = web.getHeaders().getFirst("Set-Cookie");
        assertTrue(cookie.contains("AUTH_REFRESH=refresh-secret"));
        assertTrue(cookie.contains("HttpOnly") && cookie.contains("Secure") && cookie.contains("SameSite=Lax"));
        assertTrue(cookie.contains("Path=/api/v1/auth"));
        var nativeResponse = support.tokenResponse(new Client("android",Platform.ANDROID,null),tokens);
        assertEquals("refresh-secret",nativeResponse.getBody().get("refresh_token"));
        assertNull(nativeResponse.getHeaders().getFirst("Set-Cookie"));
    }
    @Test void headerAndBodyClientMustMatchAndNativeRejectsCookies() {
        var nativeRequest = new MockHttpServletRequest();
        nativeRequest.addHeader("X-Client-Id","android");
        assertThrows(ApiProblemException.class,()->support.client(nativeRequest,"web"));
        nativeRequest.setCookies(new Cookie("anything","value"));
        nativeRequest.addHeader("Cookie","anything=value");
        assertThrows(ApiProblemException.class,()->support.client(nativeRequest,"android"));
    }
    @Test void webRequiresContextAndRejectsCredentialInBody() {
        var request = new MockHttpServletRequest(); request.addHeader("X-Client-Id","web");
        assertThrows(ApiProblemException.class,()->support.client(request,"web"));
        request.setCookies(new Cookie(WebAuthSupport.CONTEXT_COOKIE,secrets.generate()));
        Client web = support.client(request,"web");
        assertThrows(ApiProblemException.class,()->support.refresh(request,web,"token"));
    }
    @Test void metadataIsBoundedSanitizedAndIpMaskedBeforePersistence() {
        var request = new MockHttpServletRequest();
        request.addHeader("X-Client-Id","android"); request.setRemoteAddr("192.168.42.17");
        request.addHeader("User-Agent","Agent\u0001<script>" + "x".repeat(300));
        var client=support.client(request,"android"," Phone<unsafe>\n");
        assertEquals("Phoneunsafe",client.metadata().deviceLabel());
        assertEquals("192.168.42.x",client.metadata().maskedIp());
        assertEquals(256,client.metadata().userAgent().codePointCount(0,client.metadata().userAgent().length()));
        assertFalse(client.metadata().userAgent().contains("<"));
        assertFalse(client.metadata().userAgent().contains("\u0001"));
    }
}
