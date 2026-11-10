package com.d10g.ecommerce_auth.adapter.out.google;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Verifies a Google ID token against server-side registration and flow nonce.
 */
public final class GoogleIdTokenVerifier {
    private static final String GOOGLE_KEYS = "https://www.googleapis.com/oauth2/v3/certs";
    private static final Set<String> ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");
    private final JwtDecoder decoder;
    private final Clock clock;
    private final Duration skew;

    public GoogleIdTokenVerifier(Clock clock, Duration skew) {
        this(NimbusJwtDecoder.withJwkSetUri(GOOGLE_KEYS).jwsAlgorithm(SignatureAlgorithm.RS256).build(), clock, skew);
    }

    GoogleIdTokenVerifier(JwtDecoder decoder, Clock clock, Duration skew) {
        this.decoder = Objects.requireNonNull(decoder);
        this.clock = Objects.requireNonNull(clock);
        this.skew = Objects.requireNonNull(skew);
        if (skew.isNegative() || skew.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException("Clock skew must be between zero and 60 seconds");
        }
    }

    private static JwtException invalid() {
        return new JwtException("Invalid Google ID token");
    }

    public Identity verify(String rawToken, String nonce, Registration registration) {
        if (rawToken == null || rawToken.isBlank() || nonce == null || nonce.isBlank()) throw invalid();
        Jwt jwt = decoder.decode(rawToken);
        Instant now = clock.instant();
        String issuer = jwt.getClaimAsString("iss");
        String subject = jwt.getSubject();
        List<String> audience = jwt.getAudience();
        String presenter = jwt.getClaimAsString("azp");
        Instant issuedAt = jwt.getIssuedAt();
        Instant expiresAt = jwt.getExpiresAt();
        if (issuer == null || !ISSUERS.contains(issuer) || subject == null || subject.isBlank()
                || audience == null || !audience.contains(registration.audience())
                || (audience.size() > 1 && presenter == null)
                || (presenter != null && !registration.authorizedPresenters().contains(presenter))
                || issuedAt == null || issuedAt.isAfter(now.plus(skew))
                || expiresAt == null || !expiresAt.isAfter(now.minus(skew))
                || !expiresAt.isAfter(issuedAt)
                || !nonce.equals(jwt.getClaimAsString("nonce"))) {
            throw invalid();
        }
        return new Identity(subject, jwt.getClaimAsString("email"));
    }

    public record Registration(String audience, Set<String> authorizedPresenters) {
        public Registration {
            if (audience == null || audience.isBlank()) throw new IllegalArgumentException("Audience required");
            authorizedPresenters = Set.copyOf(authorizedPresenters);
        }
    }

    /**
     * Contact email remains unverified by this application.
     */
    public record Identity(String subject, String contactEmail) {
    }
}
