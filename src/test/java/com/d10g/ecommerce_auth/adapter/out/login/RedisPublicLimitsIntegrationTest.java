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
class RedisPublicLimitsIntegrationTest {
    private static LettuceConnectionFactory factory;
    private static RedisPublicLimits limits;
    @BeforeAll static void setup() {
        factory=new LettuceConnectionFactory("127.0.0.1",Integer.parseInt(System.getenv("AUTH_TEST_REDIS_PORT")));
        factory.afterPropertiesSet();factory.start();
        var redis=new StringRedisTemplate(factory);redis.afterPropertiesSet();
        limits=new RedisPublicLimits(redis,new OpaqueSecrets());
    }
    @AfterAll static void cleanup() {if(factory!=null) factory.destroy();}
    @Test void emailLimitsUseNormalizedSharedKeyAcrossIpsAndActions() {
        String id=UUID.randomUUID().toString();
        for(int i=0;i<5;i++) limits.checkEmailRequest(" "+id.toUpperCase()+"@EXAMPLE.TEST ",id+"-ip-"+i);
        assertThrows(RedisLoginLimits.RateLimitedException.class,()->limits.checkEmailRequest(id+"@example.test",id+"-new-ip"));
        limits.checkEmailRequest(UUID.randomUUID()+"@example.test",id+"-new-ip");
    }
    @Test void registrationIpBudgetIsEnforced() {
        String ip="ip-"+UUID.randomUUID();
        for(int i=0;i<50;i++) limits.checkIp(ip);
        assertThrows(RedisLoginLimits.RateLimitedException.class,()->limits.checkIp(ip));
    }
    @Test void emailQuotaCannotBeBypassedByConcurrentRequests() throws Exception {
        String email=UUID.randomUUID()+"@example.test";var pool=Executors.newFixedThreadPool(10);var start=new CountDownLatch(1);
        try {
            var results=new java.util.ArrayList<java.util.concurrent.Future<Boolean>>();
            for(int i=0;i<10;i++) {String ip="ip-"+UUID.randomUUID();results.add(pool.submit(()->{
                start.await();try {limits.checkEmailRequest(email,ip);return true;}catch(RedisLoginLimits.RateLimitedException e){return false;}
            }));}
            start.countDown();int accepted=0;for(var result:results) if(result.get(10,TimeUnit.SECONDS)) accepted++;
            assertEquals(5,accepted);
        } finally {pool.shutdownNow();}
    }
}
