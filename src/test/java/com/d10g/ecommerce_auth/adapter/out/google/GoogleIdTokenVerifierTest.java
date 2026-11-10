package com.d10g.ecommerce_auth.adapter.out.google;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;

class GoogleIdTokenVerifierTest {
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private final GoogleIdTokenVerifier.Registration registration =
            new GoogleIdTokenVerifier.Registration("server-client", Set.of("app-client"));

    private Jwt.Builder token() {
        return Jwt.withTokenValue("test").header("alg", "RS256")
                .claim("iss", "https://accounts.google.com").subject("google-subject")
                .audience(List.of("server-client")).issuedAt(NOW.minusSeconds(30))
                .expiresAt(NOW.plusSeconds(60)).claim("nonce", "challenge-nonce")
                .claim("email", "person@example.test");
    }

    private GoogleIdTokenVerifier verifier(Jwt jwt) {
        return new GoogleIdTokenVerifier(ignored -> jwt, Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofSeconds(60));
    }

    @Test
    void validatesClaimsAndReturnsStableSubject() {
        var identity = verifier(token().build()).verify("opaque", "challenge-nonce", registration);
        assertEquals("google-subject", identity.subject());
        assertEquals("person@example.test", identity.contactEmail());
    }

    @Test
    void rejectsWrongNonceAudienceAndPresenter() {
        assertThrows(JwtException.class, () -> verifier(token().build()).verify("opaque", "wrong", registration));
        assertThrows(JwtException.class, () -> verifier(token().audience(List.of("other")).build())
                .verify("opaque", "challenge-nonce", registration));
        assertThrows(JwtException.class, () -> verifier(token().claim("azp", "other").build())
                .verify("opaque", "challenge-nonce", registration));
        assertThrows(JwtException.class, () -> verifier(token().audience(List.of("server-client", "other")).build())
                .verify("opaque", "challenge-nonce", registration));
    }

    @Test
    void rejectsExpiredAndFutureTokens() {
        assertThrows(JwtException.class, () -> verifier(token().issuedAt(NOW.minusSeconds(120)).expiresAt(NOW.minusSeconds(61)).build())
                .verify("opaque", "challenge-nonce", registration));
        assertThrows(JwtException.class, () -> verifier(token().issuedAt(NOW.plusSeconds(61)).expiresAt(NOW.plusSeconds(120)).build())
                .verify("opaque", "challenge-nonce", registration));
    }
}
