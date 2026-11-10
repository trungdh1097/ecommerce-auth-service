package com.d10g.ecommerce_auth.adapter.out.login;

import static org.junit.jupiter.api.Assertions.*;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

@EnabledIfEnvironmentVariable(named="AUTH_TEST_REDIS_PORT",matches="[0-9]+")
class RedisLoginLimitsIntegrationTest {
    private static LettuceConnectionFactory factory;
    private static RedisLoginLimits limits;
    @BeforeAll static void setup() {
        factory=new LettuceConnectionFactory("127.0.0.1",Integer.parseInt(System.getenv("AUTH_TEST_REDIS_PORT")));
        factory.afterPropertiesSet(); factory.start();
        var redis=new StringRedisTemplate(factory); redis.afterPropertiesSet();
        limits=new RedisLoginLimits(redis,new OpaqueSecrets());
    }
    @AfterAll static void cleanup() { if(factory!=null) factory.destroy(); }
    @Test void concurrentFailuresAreLimitedAcrossThreads() throws Exception {
        String user="user-"+UUID.randomUUID(),ip="ip-"+UUID.randomUUID();
        var pool=Executors.newFixedThreadPool(10); var start=new CountDownLatch(1);
        try {
            var results=new java.util.ArrayList<java.util.concurrent.Future<Boolean>>();
            for(int i=0;i<10;i++) results.add(pool.submit(() -> {
                start.await();
                try { limits.checkPassword(user,ip); limits.passwordFailure(); return true; }
                catch(RedisLoginLimits.RateLimitedException blocked) { assertTrue(blocked.retryAfterSeconds()>0); return false; }
            }));
            start.countDown(); int accepted=0;
            for(var result:results) if(result.get(10,TimeUnit.SECONDS)) accepted++;
            assertEquals(5,accepted);
        } finally { pool.shutdownNow(); }
    }
    @Test void successRefundsReservationAndOtpLimitPersistsAcrossChallenges() {
        String user="user-"+UUID.randomUUID(),ip="ip-"+UUID.randomUUID();
        for(int i=0;i<8;i++) { limits.checkPassword(user,ip); limits.passwordSuccess(); }
        for(int i=0;i<5;i++) { limits.checkPassword(user,ip); limits.passwordFailure(); }
        assertThrows(RedisLoginLimits.RateLimitedException.class,()->limits.checkPassword(user,ip));
        UUID account=UUID.randomUUID();
        for(int i=0;i<5;i++) { limits.checkOtp(account,UUID.randomUUID()); limits.otpFailure(); }
        assertThrows(RedisLoginLimits.RateLimitedException.class,()->limits.checkOtp(account,UUID.randomUUID()));
    }
    @Test void mailLimitIsAtomicAndAccountScoped() {
        UUID account=UUID.randomUUID();
        for(int i=0;i<5;i++) limits.checkMail(account);
        assertThrows(RedisLoginLimits.RateLimitedException.class,()->limits.checkMail(account));
        limits.checkMail(UUID.randomUUID());
    }
}
