package com.d10g.ecommerce_auth.adapter.out.login;

import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/**
 * Atomic fixed-window reservations prevent concurrent requests from bypassing failure limits.
 */
public final class RedisLoginLimits implements LoginRateLimits {
    private static final String PREFIX = "auth:{login-limits}:";
    private static final DefaultRedisScript<Long> RESERVE = new DefaultRedisScript<>("""
            local wait = 0
            for i=1,#KEYS-1 do
              local count = tonumber(redis.call('GET', KEYS[i]) or '0')
              if count >= tonumber(ARGV[i]) then
                local ttl = redis.call('PTTL', KEYS[i]); if ttl < 1 then ttl = tonumber(ARGV[#KEYS]) end
                if ttl > wait then wait = ttl end
              end
            end
            if wait > 0 then return -wait end
            local min_ttl = tonumber(ARGV[#KEYS])
            for i=1,#KEYS-1 do
              local n = redis.call('INCR',KEYS[i])
              if n == 1 then redis.call('PEXPIRE',KEYS[i],ARGV[#KEYS]) end
              local ttl = redis.call('PTTL',KEYS[i]); if ttl < min_ttl then min_ttl = ttl end
            end
            redis.call('PSETEX',KEYS[#KEYS],math.max(1,min_ttl),'1')
            return 1
            """, Long.class);
    private static final DefaultRedisScript<Long> RELEASE = new DefaultRedisScript<>("""
            if redis.call('DEL',KEYS[#KEYS]) == 0 then return 0 end
            if ARGV[1] == 'refund' then
              for i=1,#KEYS-1 do
                local value=tonumber(redis.call('GET',KEYS[i]) or '0')
                if value > 0 then redis.call('DECR',KEYS[i]) end
              end
            end
            return 1
            """, Long.class);
    private final StringRedisTemplate redis;
    private final OpaqueSecrets secrets;
    private final ThreadLocal<List<String>> passwordReservation = new ThreadLocal<>();
    private final ThreadLocal<List<String>> otpReservation = new ThreadLocal<>();
    private final int accountMax;
    private final int ipMax;
    private final int otpMax;
    private final int mailMax;
    private final Duration attemptWindow;
    private final Duration mailWindow;

    public RedisLoginLimits(StringRedisTemplate redis, OpaqueSecrets secrets) {
        this(redis, secrets, 5, 50, 5, 5, Duration.ofMinutes(15), Duration.ofHours(1));
    }

    public RedisLoginLimits(StringRedisTemplate redis, OpaqueSecrets secrets, int accountMax, int ipMax,
                            int otpMax, int mailMax, Duration attemptWindow, Duration mailWindow) {
        this.redis = Objects.requireNonNull(redis);
        this.secrets = Objects.requireNonNull(secrets);
        if (accountMax < 1 || ipMax < 1 || otpMax < 1 || mailMax < 1 || attemptWindow.isZero() || attemptWindow.isNegative() || mailWindow.isZero() || mailWindow.isNegative())
            throw new IllegalArgumentException("Invalid limits");
        this.accountMax = accountMax;
        this.ipMax = ipMax;
        this.otpMax = otpMax;
        this.mailMax = mailMax;
        this.attemptWindow = attemptWindow;
        this.mailWindow = mailWindow;
    }

    public void checkPassword(String username, String ip) {
        Objects.requireNonNull(ip, "IP is required");
        passwordReservation.set(reserve(List.of(key("password-user", username), key("password-ip", ip)), List.of(accountMax, ipMax), attemptWindow));
    }

    public void passwordFailure() {
        finish(passwordReservation, false);
    }

    public void passwordSuccess() {
        finish(passwordReservation, true);
    }

    public void checkOtp(UUID userId, UUID challengeId) {
        otpReservation.set(reserve(List.of(key("otp-user", userId.toString()), key("otp-flow", challengeId.toString())), List.of(otpMax, otpMax), attemptWindow));
    }

    public void otpFailure() {
        finish(otpReservation, false);
    }

    public void otpSuccess() {
        finish(otpReservation, true);
    }

    public void checkMail(UUID userId) {
        List<String> reservation = reserve(List.of(key("otp-mail", userId.toString())), List.of(mailMax), mailWindow);
        release(reservation, false);
    }

    private String key(String scope, String value) {
        return PREFIX + scope + ":" + HexFormat.of().formatHex(secrets.sha256(value));
    }

    private List<String> reserve(List<String> counters, List<Integer> limits, Duration window) {
        var keys = new java.util.ArrayList<>(counters);
        keys.add(PREFIX + "reservation:" + UUID.randomUUID());
        var args = new java.util.ArrayList<String>();
        limits.forEach(limit -> args.add(limit.toString()));
        args.add(Long.toString(window.toMillis()));
        Long result = redis.execute(RESERVE, keys, args.toArray());
        if (result == null) throw new IllegalStateException("Redis rate limiter unavailable");
        if (result < 0) throw new RateLimitedException(Math.max(1, (-result + 999) / 1000));
        return List.copyOf(keys);
    }

    private void finish(ThreadLocal<List<String>> holder, boolean refund) {
        List<String> reservation = holder.get();
        holder.remove();
        if (reservation == null) throw new IllegalStateException("Missing rate limit reservation");
        release(reservation, refund);
    }

    private void release(List<String> keys, boolean refund) {
        Long result = redis.execute(RELEASE, keys, refund ? "refund" : "commit");
        if (result == null) throw new IllegalStateException("Redis rate limiter unavailable");
    }

    public static final class RateLimitedException extends RuntimeException {
        private final long retryAfterSeconds;

        public RateLimitedException(long retryAfterSeconds) {
            super("Rate limited");
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public long retryAfterSeconds() {
            return retryAfterSeconds;
        }
    }
}
