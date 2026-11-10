package com.d10g.ecommerce_auth.adapter.in.web;

import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.application.google.GoogleFlow;
import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class GoogleAuthControllerTest {
    private final FakeFlow flow = new FakeFlow();
    private final FakeSupport support = new FakeSupport();
    private final GoogleAuthController controller = new GoogleAuthController(flow, support);
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    @Test void challengeReturnsNonceAndBindingForRegisteredNativeClient() {
        var response = controller.challenge(new GoogleAuthController.ChallengeRequest("android", "My phone"), request);
        assertEquals(flow.id, response.getBody().challengeId());
        assertEquals("nonce", response.getBody().nonce());
        assertEquals("binding", response.getBody().binding());
        assertTrue(response.getHeaders().getCacheControl().contains("no-store"));
        assertEquals(1, support.rateChecks);
        assertEquals("My phone", support.deviceLabel);
    }

    @Test void exchangePendingRegistrationHasRetryAfterAndNoCredentials() {
        flow.status = GoogleFlow.Status.REGISTRATION_PENDING;
        var body = new GoogleAuthController.ExchangeRequest("android", flow.id, "binding", "google-token");
        var error = assertThrows(ApiProblemException.class, () -> controller.exchange(body, request));
        assertEquals(409, error.status());
        assertEquals("REGISTRATION_PENDING", error.code());
        assertEquals(7200, error.retryAfterSeconds());
        assertEquals(0, support.tokensIssued);
    }

    @Test void webExchangePutsRefreshOnlyInCookie() {
        support.client = new Client("web", Platform.WEB, new byte[32]);
        var body = new GoogleAuthController.ExchangeRequest("web", flow.id, null, "google-token");
        var response = controller.exchange(body, request);
        assertTrue(response.getHeaders().getFirst("Set-Cookie").contains("AUTH_REFRESH="));
        assertFalse(((java.util.Map<?, ?>) response.getBody()).containsKey("refresh_token"));
    }

    @Test void linkRequiresOnlinePrincipalAndUsesItsIdentity() {
        assertThrows(ApiProblemException.class, () -> controller.linkChallenge(new GoogleAuthController.ChallengeRequest("android"), null, request));
        var principal = new AuthPrincipal(UUID.randomUUID(), UUID.randomUUID());
        controller.linkChallenge(new GoogleAuthController.ChallengeRequest("android"), principal, request);
        assertEquals(principal.userId(), flow.principal.userId());
        assertEquals(principal.sessionId(), flow.principal.sessionId());
    }

    private static class FakeSupport extends WebAuthSupport {
        Client client = new Client("android", Platform.ANDROID, null);
        int rateChecks, tokensIssued;
        String deviceLabel;
        FakeSupport() { super(null, null, null, null); }
        @Override public void checkIp(HttpServletRequest request) { rateChecks++; }
        @Override public Client client(HttpServletRequest request, String id) {
            if (!id.equals(client.clientId())) throw new AssertionError("client mismatch");
            return client;
        }
        @Override public Client client(HttpServletRequest request, String id, String label) {
            deviceLabel = label;
            return client(request, id);
        }
        @Override public org.springframework.http.ResponseEntity<java.util.Map<String,Object>> tokenResponse(Client c, Tokens t) {
            tokensIssued++;
            return super.tokenResponse(c, t);
        }
    }
    private static class FakeFlow implements GoogleFlow {
        UUID id = UUID.randomUUID();
        Status status = Status.SUCCESS;
        Principal principal;
        public Challenge challenge(Client client, Principal principal) {
            this.principal = principal;
            return new Challenge(status, id, "nonce", "binding", Instant.now().plusSeconds(300));
        }
        public Result exchange(Client client, UUID challengeId, String binding, String token) {
            return new Result(status, status == Status.SUCCESS ? new Tokens("access", "refresh", UUID.randomUUID(), 300) : null, 7200);
        }
        public Result link(Client client, Principal principal, UUID challengeId, String binding, String token) {
            this.principal = principal;
            return new Result(status, null, 0);
        }
    }
}
