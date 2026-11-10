package com.d10g.ecommerce_auth.application.audit;

import java.util.UUID;

/**
 * Restricted audit attributes: never pass credentials, OTP, URLs or request bodies.
 */
public interface AuditPort {
    void record(EventType event, UUID userId, UUID sessionId, Outcome outcome, String traceId);

    enum EventType {
        LOGIN_SUCCESS, LOGIN_FAILURE, OTP_BLOCKED, SESSION_REPLACED, SESSION_REVOKED,
        LOGOUT_ALL, PASSWORD_RESET, PASSWORD_CHANGE, IDENTITY_LINK, REFRESH_REUSE
    }

    enum Outcome {SUCCESS, FAILURE}
}
