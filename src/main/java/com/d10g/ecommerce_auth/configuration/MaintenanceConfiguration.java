package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcRetentionCleanup;
import com.d10g.ecommerce_auth.adapter.out.maintenance.JdbcAuditRecorder;
import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.time.Duration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(MaintenanceConfiguration.Properties.class)
public class MaintenanceConfiguration {
    @Bean
    AuditPort auditPort(JdbcTemplate db) {
        return new JdbcAuditRecorder(db, new OpaqueSecrets());
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.cleanup", name = "enabled", havingValue = "true", matchIfMissing = true)
    JdbcRetentionCleanup jdbcRetentionCleanup(JdbcTemplate db, PlatformTransactionManager manager, Properties properties) {
        return new JdbcRetentionCleanup(db, new TransactionTemplate(manager), properties.getBatchSize(),
                properties.getChallengeRetention(), properties.getHistoryRetention(), properties.getClockSkew());
    }

    @ConfigurationProperties(prefix = "auth.cleanup")
    public static class Properties {
        private int batchSize = 100;
        private Duration challengeRetention = Duration.ofHours(24);
        private Duration historyRetention = Duration.ofDays(90);
        private Duration clockSkew = Duration.ofSeconds(60);

        public int getBatchSize() {
            return batchSize;
        }

        public void setBatchSize(int batchSize) {
            this.batchSize = batchSize;
        }

        public Duration getChallengeRetention() {
            return challengeRetention;
        }

        public void setChallengeRetention(Duration challengeRetention) {
            this.challengeRetention = challengeRetention;
        }

        public Duration getHistoryRetention() {
            return historyRetention;
        }

        public void setHistoryRetention(Duration historyRetention) {
            this.historyRetention = historyRetention;
        }

        public Duration getClockSkew() {
            return clockSkew;
        }

        public void setClockSkew(Duration clockSkew) {
            this.clockSkew = clockSkew;
        }
    }
}
