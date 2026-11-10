package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes only RSA public keys; absent key configuration is a service outage.
 */
@RestController
public final class JwksController {
    private final ObjectProvider<RsaAccessTokens> keys;

    public JwksController(ObjectProvider<RsaAccessTokens> keys) {
        this.keys = keys;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> keys() {
        RsaAccessTokens configured = keys.getIfAvailable();
        if (configured == null) return ResponseEntity.status(503).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(configured.publicJwks());
    }
}
