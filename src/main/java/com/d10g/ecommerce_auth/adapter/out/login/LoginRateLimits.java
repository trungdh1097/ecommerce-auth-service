package com.d10g.ecommerce_auth.adapter.out.login;

import java.util.UUID;

/**
 * Atomic reservations across instances. All failures must propagate to fail closed.
 */
public interface LoginRateLimits {
    void checkPassword(String username, String ip);

    void passwordFailure();

    void passwordSuccess();

    void checkOtp(UUID userId, UUID challengeId);

    void otpFailure();

    void otpSuccess();

    void checkMail(UUID userId);
}
