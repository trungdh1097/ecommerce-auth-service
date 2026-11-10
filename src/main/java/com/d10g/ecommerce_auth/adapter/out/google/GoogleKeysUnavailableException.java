package com.d10g.ecommerce_auth.adapter.out.google;

/**
 * Google signing keys could not be retrieved, so the token cannot be validated.
 */
public final class GoogleKeysUnavailableException extends RuntimeException {
    public GoogleKeysUnavailableException(Throwable cause) {
        super("Google signing keys unavailable", cause);
    }
}
