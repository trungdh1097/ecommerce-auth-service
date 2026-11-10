package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.in.web.RoleController;
import com.d10g.ecommerce_auth.adapter.out.account.JdbcAccountAdapter;
import com.d10g.ecommerce_auth.adapter.out.notification.OutboxKeyRing;
import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.account.AccountService;
import com.d10g.ecommerce_auth.application.role.RoleService;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

import static org.assertj.core.api.Assertions.assertThat;

class AuthRuntimeConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(AuthRuntimeConfiguration.class, RoleController.class);

    @Test void runtimeDisabledDoesNotRequireInfrastructureOrRegisterRoleBeans() {
        runner.withPropertyValues("auth.runtime.enabled=false").run(context -> {
            assertThat(context).hasNotFailed().doesNotHaveBean(RoleController.class)
                    .doesNotHaveBean(RoleService.class).doesNotHaveBean(JdbcAccountAdapter.class);
        });
    }

    @Test void runtimeEnabledWiresRoleControllerAndValidatesIdentifiers() {
        enabledRuntime().run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(RoleController.class)
                    .hasSingleBean(RoleService.class).hasSingleBean(AccountService.class)
                    .hasSingleBean(JdbcAccountAdapter.class);
            var service = context.getBean(RoleService.class);
            assertThat(service.changeRole(null, 1)).isEqualTo(RoleService.Result.INVALID_USERID);
            assertThat(service.changeRole(UUID.randomUUID(), null)).isEqualTo(RoleService.Result.INVALID_ROLE);
        });
    }

    @Test void accountServiceStillRequiresAnEmailWorker() {
        enabledRuntime().withPropertyValues("auth.outbox.external-worker=false").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasRootCauseInstanceOf(IllegalStateException.class)
                    .hasRootCauseMessage("Enable the email worker or explicitly configure an external worker");
        });
    }

    private ApplicationContextRunner enabledRuntime() {
        String key = Base64.getEncoder().encodeToString(new byte[32]);
        return runner.withPropertyValues("auth.runtime.enabled=true", "auth.outbox.external-worker=true",
                        "auth.runtime.otp-hmac-key=" + key, "auth.runtime.clients.android.platform=ANDROID")
                .withBean(JdbcTemplate.class, () -> new JdbcTemplate() {
                    @Override public void afterPropertiesSet() { }
                })
                .withBean(StringRedisTemplate.class, () -> new StringRedisTemplate() {
                    @Override public void afterPropertiesSet() { }
                })
                .withBean(MeterRegistry.class, SimpleMeterRegistry::new)
                .withBean(OutboxKeyRing.class, () -> new OutboxKeyRing("test", Map.of("test", key)))
                .withBean(RsaAccessTokens.class, AuthRuntimeConfigurationTest::tokens)
                .withBean(PlatformTransactionManager.class, () -> new PlatformTransactionManager() {
                    public TransactionStatus getTransaction(TransactionDefinition definition) { return new SimpleTransactionStatus(); }
                    public void commit(TransactionStatus status) { }
                    public void rollback(TransactionStatus status) { }
                });
    }

    private static RsaAccessTokens tokens() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            return new RsaAccessTokens("issuer", "audience", "test", (RSAPrivateKey) pair.getPrivate(),
                    Map.of("test", (RSAPublicKey) pair.getPublic()), Clock.systemUTC());
        } catch (GeneralSecurityException e) {
            throw new AssertionError(e);
        }
    }
}
