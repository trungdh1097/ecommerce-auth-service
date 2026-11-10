package com.d10g.ecommerce_auth.adapter.out.login;

import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.util.Objects;
import java.util.UUID;

import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Crypto primitives for the login adapter; the HMAC key is injected from the secret store.
 */
public final class LoginCrypto {
    private final PasswordEncoder passwordEncoder;
    private final OpaqueSecrets secrets;
    private final byte[] otpKey;
    private final String dummyPasswordHash;

    public LoginCrypto(PasswordEncoder passwordEncoder, OpaqueSecrets secrets, byte[] otpKey) {
        this.passwordEncoder = Objects.requireNonNull(passwordEncoder);
        this.secrets = Objects.requireNonNull(secrets);
        if (otpKey == null || otpKey.length < 32)
            throw new IllegalArgumentException("OTP HMAC key must be at least 256 bits");
        this.otpKey = otpKey.clone();
        this.dummyPasswordHash = passwordEncoder.encode(secrets.generate());
    }

    public String dummyPasswordHash() {
        return dummyPasswordHash;
    }

    public boolean passwordMatches(String password, String hash) {
        return passwordEncoder.matches(password, hash);
    }

    public String newNativeBinding() {
        return secrets.generate();
    }

    public String newOtp() {
        return secrets.randomDigits(6);
    }

    public byte[] hashBinding(String binding) {
        return secrets.sha256(binding);
    }

    public byte[] otpMac(UUID challengeId, int generation, String otp) {
        return secrets.hmacSha256("login-otp:" + challengeId + ":" + generation + ":" + otp, otpKey);
    }

    public boolean constantTimeEquals(byte[] expected, byte[] actual) {
        return secrets.matches(expected, actual);
    }
}
