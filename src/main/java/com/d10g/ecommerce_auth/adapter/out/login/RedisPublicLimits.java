package com.d10g.ecommerce_auth.adapter.out.login;

import com.d10g.ecommerce_auth.domain.account.Account;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

/**
 * Distributed public-request limits. No database lookup is needed, including for unknown emails.
 */
public final class RedisPublicLimits {
    private static final String PREFIX = "auth:{public-limits}:";
    private static final DefaultRedisScript<Long> CHECK = new DefaultRedisScript<>("""
            local wait = 0
            for i=1,#KEYS do
              local n=tonumber(redis.call('GET',KEYS[i]) or '0')
              if n>=tonumber(ARGV[2*i-1]) then
                local ttl=redis.call('PTTL',KEYS[i]); if ttl < 1 then ttl=tonumber(ARGV[2*i]) end
                if ttl > wait then wait=ttl end
              end
            end
            if wait>0 then return -wait end
            for i=1,#KEYS do
              local n=redis.call('INCR',KEYS[i]); if n==1 then redis.call('PEXPIRE',KEYS[i],ARGV[2*i]) end
            end
            return 1
            """, Long.class);
    private final StringRedisTemplate redis;
    private final OpaqueSecrets secrets;
    private final int emailLimit;
    private final int ipLimit;
    private final Duration emailWindow, ipWindow;

    public RedisPublicLimits(StringRedisTemplate redis, OpaqueSecrets secrets) {
        this(redis, secrets, 5, 50, Duration.ofHours(1), Duration.ofMinutes(15));
    }

    public RedisPublicLimits(StringRedisTemplate redis, OpaqueSecrets secrets, int emailLimit, int ipLimit, Duration emailWindow, Duration ipWindow) {
        this.redis = Objects.requireNonNull(redis);
        this.secrets = Objects.requireNonNull(secrets);
        if (emailLimit < 1 || ipLimit < 1 || emailWindow.isNegative() || emailWindow.isZero() || ipWindow.isNegative() || ipWindow.isZero())
            throw new IllegalArgumentException("Invalid public rate limits");
        this.emailLimit = emailLimit;
        this.ipLimit = ipLimit;
        this.emailWindow = emailWindow;
        this.ipWindow = ipWindow;
    }

    private static String requireIp(String ip) {
        if (ip == null || ip.isBlank()) throw new IllegalArgumentException("IP required");
        return ip;
    }

    /**
     * Forgot and resend share the same email quota regardless of account existence.
     */
    public void checkEmailRequest(String email, String ip) {
        String normalized = Account.normalizeEmail(email);
        evaluate(List.of(key("mail", normalized), key("ip", requireIp(ip))),
                Integer.toString(emailLimit), Long.toString(emailWindow.toMillis()), Integer.toString(ipLimit), Long.toString(ipWindow.toMillis()));
    }

    /**
     * Public API callers, including registration, can apply the common IP budget.
     */
    public void checkIp(String ip) {
        evaluate(List.of(key("ip", requireIp(ip))), Integer.toString(ipLimit), Long.toString(ipWindow.toMillis()));
    }

    private void evaluate(List<String> keys, String... args) {
        Long result = redis.execute(CHECK, keys, (Object[]) args);
        if (result == null) throw new IllegalStateException("Redis rate limiter unavailable");
        if (result < 0) throw new RedisLoginLimits.RateLimitedException(Math.max(1, (-result + 999) / 1000));
    }

    private String key(String scope, String value) {
        return PREFIX + scope + ":" + HexFormat.of().formatHex(secrets.sha256(value));
    }
}
