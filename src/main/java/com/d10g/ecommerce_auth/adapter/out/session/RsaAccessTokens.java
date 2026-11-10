package com.d10g.ecommerce_auth.adapter.out.session;

import com.d10g.ecommerce_auth.application.session.SessionPorts.AccessTokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.ActiveSession;
import com.d10g.ecommerce_auth.application.session.SessionPorts.VerifiedAccessToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * RS256 signing and verification with separately injected private and published public keys.
 */
public final class RsaAccessTokens implements AccessTokens {
    private static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(60);
    private final String issuer;
    private final String audience;
    private final String activeKeyId;
    private final RSAPrivateKey signingKey;
    private final Map<String, RSAPublicKey> publicKeys;
    private final Clock clock;

    public RsaAccessTokens(String issuer, String audience, String activeKeyId, RSAPrivateKey signingKey,
                           Map<String, RSAPublicKey> publicKeys, Clock clock) {
        this.issuer = requireText(issuer, "issuer");
        this.audience = requireText(audience, "audience");
        this.activeKeyId = requireText(activeKeyId, "activeKeyId");
        this.signingKey = Objects.requireNonNull(signingKey);
        this.publicKeys = Map.copyOf(publicKeys);
        this.clock = Objects.requireNonNull(clock);
        RSAPublicKey active = this.publicKeys.get(activeKeyId);
        if (active == null || !active.getModulus().equals(signingKey.getModulus()) || active.getModulus().bitLength() < 2048) {
            throw new IllegalArgumentException("active RSA key pair must match and be at least 2048 bits");
        }
        if (this.publicKeys.entrySet().stream().anyMatch(e -> e.getKey().isBlank() || e.getValue().getModulus().bitLength() < 2048)) {
            throw new IllegalArgumentException("public keys must have IDs and be at least 2048 bits");
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(name + " required");
        return value;
    }

    @Override
    public String sign(ActiveSession session, Instant issuedAt, Instant expiresAt) {
        Objects.requireNonNull(session);
        if (!expiresAt.isAfter(issuedAt)) throw new IllegalArgumentException("expiry must follow issue time");
        List<String> methods = Arrays.stream(session.authenticationMethod().split("[ ,]+"))
                .filter(value -> !value.isBlank()).toList();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(session.userId().toString()).issuer(issuer).audience(audience)
                .issueTime(Date.from(issuedAt)).expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString()).claim("sid", session.sessionId().toString())
                .claim("auth_version", session.authVersion())
                .claim("auth_time", session.authTime().getEpochSecond()).claim("amr", methods).build();
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(activeKeyId).type(com.nimbusds.jose.JOSEObjectType.JWT).build(), claims);
        try {
            jwt.sign(new RSASSASigner(signingKey));
            return jwt.serialize();
        } catch (JOSEException ex) {
            throw new IllegalStateException("Access token signing failed", ex);
        }
    }

    @Override
    public VerifiedAccessToken verify(String token) {
        if (token == null || token.isBlank()) return null;
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) return null;
            RSAPublicKey key = publicKeys.get(jwt.getHeader().getKeyID());
            if (key == null || !jwt.verify(new RSASSAVerifier(key))) return null;
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant now = clock.instant();
            Date expiry = claims.getExpirationTime();
            Date issuedAt = claims.getIssueTime();
            Date notBefore = claims.getNotBeforeTime();
            if (!issuer.equals(claims.getIssuer()) || claims.getAudience() == null || !claims.getAudience().contains(audience)
                    || expiry == null || issuedAt == null || claims.getJWTID() == null || claims.getJWTID().isBlank()
                    || !now.isBefore(expiry.toInstant().plus(MAX_CLOCK_SKEW))
                    || issuedAt.toInstant().isAfter(now.plus(MAX_CLOCK_SKEW))
                    || (notBefore != null && notBefore.toInstant().isAfter(now.plus(MAX_CLOCK_SKEW)))) return null;
            UUID user = UUID.fromString(claims.getSubject());
            UUID session = UUID.fromString(claims.getStringClaim("sid"));
            Long version = claims.getLongClaim("auth_version");
            if (version == null || version < 0) return null;
            return new VerifiedAccessToken(user, session, version, expiry.toInstant());
        } catch (ParseException | JOSEException | IllegalArgumentException | NullPointerException ex) {
            return null;
        }
    }

    /**
     * Returns public material only. Previously active public keys remain publishable during rotation.
     */
    public String publicJwks() {
        List<JWK> keys = publicKeys.entrySet().stream().sorted(Map.Entry.comparingByKey())
                .map(entry -> (JWK) new RSAKey.Builder(entry.getValue()).keyID(entry.getKey())
                        .keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build()).toList();
        return new JWKSet(keys).toString();
    }
}
