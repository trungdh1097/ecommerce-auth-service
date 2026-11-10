package com.d10g.ecommerce_auth.application.google;

import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;

import java.time.Instant;
import java.util.UUID;

/**
 * Port for Google authentication. Identity verification and all state changes are server controlled.
 */
public interface GoogleFlow {
    /**
     * principal is null for login; LINK requires a principal derived from an authenticated token.
     */
    Challenge challenge(Client client, Principal principal);

    Result exchange(Client client, UUID challengeId, String nativeBinding, String googleIdToken);

    Result link(Client client, Principal principal, UUID challengeId, String nativeBinding, String googleIdToken);

    enum Status {SUCCESS, INVALID, EXPIRED, ACCOUNT_LINK_REQUIRED, REGISTRATION_PENDING, REAUTHENTICATION_REQUIRED, IDENTITY_CONFLICT}

    record Principal(UUID userId, UUID sessionId) {
    }

    record Challenge(Status status, UUID id, String nonce, String nativeBinding, Instant expiresAt) {
    }

    record Result(Status status, Tokens tokens, long retryAfterSeconds) {
    }
}
