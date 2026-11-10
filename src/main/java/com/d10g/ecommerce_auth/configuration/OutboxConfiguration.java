package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.out.notification.EmailNotificationSender;
import com.d10g.ecommerce_auth.adapter.out.notification.EmailOutboxWorker;
import com.d10g.ecommerce_auth.adapter.out.notification.OutboxKeyRing;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(OutboxConfiguration.Properties.class)
public class OutboxConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "auth.outbox", name = "active-key-id")
    public OutboxKeyRing outboxKeyRing(Properties properties) {
        return new OutboxKeyRing(properties.getActiveKeyId(), properties.getKeys());
    }

    @Bean
    @ConditionalOnProperty(prefix = "auth.outbox", name = "enabled", havingValue = "true")
    EmailOutboxWorker emailOutboxWorker(JdbcTemplate jdbc, PlatformTransactionManager manager,
                                        OutboxKeyRing keys, JavaMailSender mail, Properties properties) {
        // Worker holds database locks during delivery, so SMTP must have finite timeouts.
        if (mail instanceof JavaMailSenderImpl smtp) {
            smtp.getJavaMailProperties().putIfAbsent("mail.smtp.connectiontimeout", "5000");
            smtp.getJavaMailProperties().putIfAbsent("mail.smtp.timeout", "5000");
            smtp.getJavaMailProperties().putIfAbsent("mail.smtp.writetimeout", "5000");
        }
        var sender = new EmailNotificationSender(mail, properties.getFrom(), properties.getVerifyUrl(), properties.getResetUrl());
        return new EmailOutboxWorker(jdbc, new TransactionTemplate(manager), keys, sender,
                properties.getBatchSize(), properties.getMaxAttempts(), properties.getRetryDelay());
    }

    @ConfigurationProperties(prefix = "auth.outbox")
    public static class Properties {
        private String activeKeyId;
        private Map<String, String> keys = new HashMap<>();
        private String from;
        private String verifyUrl;
        private String resetUrl;
        private int batchSize = 50;
        private int maxAttempts = 5;
        private Duration retryDelay = Duration.ofSeconds(30);

        public String getActiveKeyId() {
            return activeKeyId;
        }

        public void setActiveKeyId(String activeKeyId) {
            this.activeKeyId = activeKeyId;
        }

        public Map<String, String> getKeys() {
            return keys;
        }

        public void setKeys(Map<String, String> keys) {
            this.keys = keys;
        }

        public String getFrom() {
            return from;
        }

        public void setFrom(String from) {
            this.from = from;
        }

        public String getVerifyUrl() {
            return verifyUrl;
        }

        public void setVerifyUrl(String verifyUrl) {
            this.verifyUrl = verifyUrl;
        }

        public String getResetUrl() {
            return resetUrl;
        }

        public void setResetUrl(String resetUrl) {
            this.resetUrl = resetUrl;
        }

        public int getBatchSize() {
            return batchSize;
        }

        public void setBatchSize(int batchSize) {
            this.batchSize = batchSize;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getRetryDelay() {
            return retryDelay;
        }

        public void setRetryDelay(Duration retryDelay) {
            this.retryDelay = retryDelay;
        }
    }
}
