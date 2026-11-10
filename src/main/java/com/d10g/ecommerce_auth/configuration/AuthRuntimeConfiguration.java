package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.in.web.ClientRegistry;
import com.d10g.ecommerce_auth.adapter.out.account.JdbcAccountAdapter;
import com.d10g.ecommerce_auth.adapter.out.google.GoogleIdTokenVerifier;
import com.d10g.ecommerce_auth.adapter.out.google.JdbcGoogleFlow;
import com.d10g.ecommerce_auth.adapter.out.login.JdbcLoginAdapter;
import com.d10g.ecommerce_auth.adapter.out.login.LoginCrypto;
import com.d10g.ecommerce_auth.adapter.out.login.RedisLoginLimits;
import com.d10g.ecommerce_auth.adapter.out.login.RedisPublicLimits;
import com.d10g.ecommerce_auth.adapter.out.notification.OutboxKeyRing;
import com.d10g.ecommerce_auth.adapter.out.role.JdbcRoleAdapter;
import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionIssuer;
import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionStore;
import com.d10g.ecommerce_auth.adapter.out.session.JdbcSessionManagementStore;
import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.account.AccountService;
import com.d10g.ecommerce_auth.application.google.GoogleFlow;
import com.d10g.ecommerce_auth.application.login.LoginService;
import com.d10g.ecommerce_auth.application.role.RoleService;
import com.d10g.ecommerce_auth.application.session.SessionPorts;
import com.d10g.ecommerce_auth.application.session.SessionService;
import com.d10g.ecommerce_auth.application.session.SessionManagementService;
import com.d10g.ecommerce_auth.application.observability.AuthMetrics;
import com.d10g.ecommerce_auth.adapter.out.observability.MicrometerAuthMetrics;
import io.micrometer.core.instrument.MeterRegistry;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Explicit composition root. Incomplete runtime configuration fails startup rather than weakening security.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(AuthRuntimeConfiguration.Properties.class)
public class AuthRuntimeConfiguration {
    @Bean
    OpaqueSecrets opaqueSecrets() {
        return new OpaqueSecrets();
    }

    @Bean
    AuthMetrics authMetrics(MeterRegistry registry) {
        return new MicrometerAuthMetrics(registry);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new Argon2PasswordEncoder(16, 32, 1, 19 * 1024, 2);
    }

    @Bean
    RedisPublicLimits redisPublicLimits(StringRedisTemplate redis, OpaqueSecrets secrets) {
        return new RedisPublicLimits(redis, secrets);
    }

    @Bean
    ClientRegistry clientRegistry(Properties p) {
        return new ClientRegistry(p.getClients(), p.getAllowedOrigins());
    }

    @Bean
    SessionService sessionService(JdbcTemplate db, PlatformTransactionManager tm, RsaAccessTokens jwt, OpaqueSecrets secrets, AuthMetrics metrics) {
        var template = new TransactionTemplate(tm);
        SessionPorts.Transaction tx = new SessionPorts.Transaction() {
            public <T> T execute(Supplier<T> work) {
                return template.execute(status -> work.get());
            }
        };
        SessionPorts.Secrets refresh = new SessionPorts.Secrets() {
            public String newRefreshToken() {
                return secrets.generate();
            }

            public byte[] hash(String value) {
                return secrets.sha256(value);
            }
        };
        return new SessionService(tx, new JdbcSessionStore(db), refresh, jwt, Clock.systemUTC(), metrics);
    }

    @Bean
    SessionManagementService sessionManagementService(JdbcTemplate db, PlatformTransactionManager tm) {
        return new SessionManagementService(new JdbcSessionManagementStore(db, new TransactionTemplate(tm)));
    }

    @Bean
    JdbcSessionIssuer jdbcSessionIssuer(JdbcTemplate db, RsaAccessTokens jwt, OpaqueSecrets secrets) {
        return new JdbcSessionIssuer(db, secrets, jwt);
    }

    @Bean
    JdbcAccountAdapter jdbcAccountAdapter(JdbcTemplate db, PlatformTransactionManager tm, PasswordEncoder password,
                                         OpaqueSecrets secrets, OutboxKeyRing keys) {
        return new JdbcAccountAdapter(db, new TransactionTemplate(tm), password, secrets, keys.activeCipher(), keys.activeKeyId());
    }

    @Bean
    AccountService accountService(JdbcAccountAdapter accounts,
                                  @Value("${auth.outbox.enabled:false}") boolean workerEnabled,
                                  @Value("${auth.outbox.external-worker:false}") boolean externalWorker) {
        if (!workerEnabled && !externalWorker) {
            throw new IllegalStateException("Enable the email worker or explicitly configure an external worker");
        }
        return new AccountService(accounts);
    }

    @Bean
    RoleService roleService(JdbcTemplate db, PlatformTransactionManager tm, JdbcAccountAdapter accounts) {
        return new RoleService(new JdbcRoleAdapter(db, new TransactionTemplate(tm)), accounts);
    }

    @Bean
    LoginService loginService(JdbcTemplate db, PlatformTransactionManager tm, PasswordEncoder password,
                              OpaqueSecrets secrets, OutboxKeyRing keys, JdbcSessionIssuer issuer,
                              StringRedisTemplate redis, Properties p, AuthMetrics metrics,
                              @Value("${auth.runtime.trusted-device-ttl:P90D}") String trustedDeviceTtl) {
        if (p.getOtpHmacKey() == null) throw new IllegalStateException("auth.runtime.otp-hmac-key is required");
        var crypto = new LoginCrypto(password, secrets, Base64.getDecoder().decode(p.getOtpHmacKey()));
        return new LoginService(new JdbcLoginAdapter(db, new TransactionTemplate(tm), crypto, secrets,
                keys.activeCipher(), keys.activeKeyId(), issuer, new RedisLoginLimits(redis, secrets)), metrics, Duration.parse(trustedDeviceTtl));
    }

    @Bean
    GoogleFlow googleFlow(JdbcTemplate db, PlatformTransactionManager tm, OpaqueSecrets secrets,
                          JdbcSessionIssuer issuer, Properties p) {
        Map<String, JdbcGoogleFlow.Registration> google = new HashMap<>();
        p.getClients().forEach((id, c) -> {
            if (c.googleAudience() != null && !c.googleAudience().isBlank())
                google.put(id, new JdbcGoogleFlow.Registration(c.platform(),
                        new GoogleIdTokenVerifier.Registration(c.googleAudience(), c.googlePresenters())));
        });
        return new JdbcGoogleFlow(db, new TransactionTemplate(tm), secrets,
                new GoogleIdTokenVerifier(Clock.systemUTC(), Duration.ofSeconds(60)), issuer, google);
    }

    @ConfigurationProperties(prefix = "auth.runtime")
    public static class Properties {
        private Map<String, ClientRegistry.Registration> clients = new HashMap<>();
        private Set<String> allowedOrigins = new HashSet<>();
        private String otpHmacKey;

        public Map<String, ClientRegistry.Registration> getClients() {
            return clients;
        }

        public void setClients(Map<String, ClientRegistry.Registration> clients) {
            this.clients = clients;
        }

        public Set<String> getAllowedOrigins() {
            return allowedOrigins;
        }

        public void setAllowedOrigins(Set<String> allowedOrigins) {
            this.allowedOrigins = allowedOrigins;
        }

        public String getOtpHmacKey() {
            return otpHmacKey;
        }

        public void setOtpHmacKey(String otpHmacKey) {
            this.otpHmacKey = otpHmacKey;
        }
    }
}
