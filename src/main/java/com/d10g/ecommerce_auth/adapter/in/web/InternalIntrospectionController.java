package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.session.SessionService;
import jakarta.servlet.http.HttpServletRequest;

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Internal endpoint accepts only a TLS client whose leaf certificate is explicitly pinned.
 */
@RestController
@ConditionalOnProperty(prefix = "auth.internal", name = "enabled", havingValue = "true")
public class InternalIntrospectionController {
    private final Set<String> allowed;
    private final RsaAccessTokens tokens;
    private final SessionService sessions;

    public InternalIntrospectionController(RsaAccessTokens tokens, SessionService sessions,
                                           @Value("${auth.internal.client-certificate-sha256:}") String fingerprints) {
        this.tokens = tokens;
        this.sessions = sessions;
        this.allowed = Arrays.stream(fingerprints.split(","))
                .map(s -> s.trim().toLowerCase(java.util.Locale.ROOT).replace(":", ""))
                .filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
        if (allowed.isEmpty() || allowed.stream().anyMatch(s -> !s.matches("[0-9a-f]{64}")))
            throw new IllegalArgumentException("At least one SHA-256 client certificate fingerprint is required");
    }

    @PostMapping("/internal/v1/auth/introspect")
    public ResponseEntity<Result> introspect(HttpServletRequest request, @RequestBody Request input) {
        if (!authenticated(request)) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        var token = input == null ? null : input.token();
        try {
            var verified = tokens.verify(token);
            if (verified == null || !sessions.introspect(token))
                return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(Result.inactive());
            return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                    .body(new Result(true, verified.userId(), verified.sessionId(), verified.expiresAt()));
        } catch (org.springframework.dao.DataAccessException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    private boolean authenticated(HttpServletRequest request) {
        if (!request.isSecure()) return false;
        Object attribute = request.getAttribute("jakarta.servlet.request.X509Certificate");
        if (!(attribute instanceof X509Certificate[] chain) || chain.length == 0 || chain[0] == null) return false;
        try {
            chain[0].checkValidity();
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded()));
            return allowed.contains(digest);
        } catch (CertificateException | java.security.NoSuchAlgorithmException ex) {
            return false;
        }
    }

    public record Request(String token) {
    }

    public record Result(boolean active, UUID user_id, UUID session_id, Instant expires_at) {
        static Result inactive() {
            return new Result(false, null, null, null);
        }
    }
}
