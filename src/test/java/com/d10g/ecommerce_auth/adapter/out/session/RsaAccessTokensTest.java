package com.d10g.ecommerce_auth.adapter.out.session;

import static org.junit.jupiter.api.Assertions.*;

import com.d10g.ecommerce_auth.application.session.SessionPorts.ActiveSession;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class RsaAccessTokensTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static KeyPair first;
    private static KeyPair second;
    private final UUID user = UUID.randomUUID(), sessionId = UUID.randomUUID();
    private final ActiveSession session = new ActiveSession(user, sessionId, "web", Platform.WEB, 7,
            NOW.minusSeconds(10), "password otp", NOW.plusSeconds(600), NOW, true, true, 7);
    @BeforeAll static void generateKeys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048);
        first = generator.generateKeyPair(); second = generator.generateKeyPair();
    }
    private RsaAccessTokens tokens(KeyPair pair, String id, Map<String, RSAPublicKey> keys, String issuer, String audience, Instant now) {
        return new RsaAccessTokens(issuer, audience, id, (RSAPrivateKey) pair.getPrivate(), keys, Clock.fixed(now, ZoneOffset.UTC));
    }
    @Test void signedClaimsCanBeVerifiedWithoutPersonalData() throws Exception {
        var keys = Map.of("one", (RSAPublicKey) first.getPublic());
        var tokens = tokens(first, "one", keys, "issuer", "api", NOW);
        String raw = tokens.sign(session, NOW, NOW.plusSeconds(300));
        var result = tokens.verify(raw);
        assertNotNull(result);
        assertEquals(user, result.userId()); assertEquals(sessionId, result.sessionId()); assertEquals(7, result.authVersion());
        var claims = SignedJWT.parse(raw).getJWTClaimsSet();
        assertEquals("issuer", claims.getIssuer()); assertEquals(java.util.List.of("password", "otp"), claims.getStringListClaim("amr"));
        assertNull(claims.getClaim("email"));
        assertFalse(tokens.publicJwks().contains("\"d\":"));
    }
    @Test void issuerAudienceSignatureAndExpiryAreEnforced() {
        var keys = Map.of("one", (RSAPublicKey) first.getPublic());
        var signer = tokens(first, "one", keys, "issuer", "api", NOW);
        String raw = signer.sign(session, NOW, NOW.plusSeconds(300));
        assertNull(tokens(first, "one", keys, "other", "api", NOW).verify(raw));
        assertNull(tokens(first, "one", keys, "issuer", "other", NOW).verify(raw));
        assertNull(tokens(first, "one", keys, "issuer", "api", NOW.plusSeconds(361)).verify(raw));
        String tampered = raw.substring(0, raw.lastIndexOf('.') + 1) + "invalid";
        assertNull(signer.verify(tampered));
        assertNull(signer.verify("not-a-jwt"));
    }
    @Test void keyRotationKeepsOldPublicKeyAndRejectsUnknownKid() {
        var oldKeys = Map.of("old", (RSAPublicKey) first.getPublic());
        var old = tokens(first, "old", oldKeys, "issuer", "api", NOW);
        String raw = old.sign(session, NOW, NOW.plusSeconds(300));
        var rotated = tokens(second, "new", Map.of("old", (RSAPublicKey) first.getPublic(), "new", (RSAPublicKey) second.getPublic()), "issuer", "api", NOW);
        assertNotNull(rotated.verify(raw));
        assertNull(tokens(second, "new", Map.of("new", (RSAPublicKey) second.getPublic()), "issuer", "api", NOW).verify(raw));
        assertThrows(IllegalArgumentException.class, () -> tokens(first, "bad", Map.of("bad", (RSAPublicKey) second.getPublic()), "issuer", "api", NOW));
    }
}
