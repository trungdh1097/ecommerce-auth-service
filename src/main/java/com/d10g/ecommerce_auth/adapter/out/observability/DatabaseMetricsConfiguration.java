package com.d10g.ecommerce_auth.adapter.out.observability;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Database-backed gauges return NaN, not a false zero, during outages.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class DatabaseMetricsConfiguration {
    private static double query(JdbcTemplate jdbc, MeterRegistry registry, String sql) {
        try {
            Number number = jdbc.queryForObject(sql, Number.class);
            return number == null ? Double.NaN : number.doubleValue();
        } catch (DataAccessException ex) {
            registry.counter("auth.database.errors").increment();
            return Double.NaN;
        }
    }

    @Bean
    MeterBinder authDatabaseGauges(JdbcTemplate jdbc) {
        return registry -> {
            Gauge.builder("auth.sessions.active", jdbc, db -> query(db, registry,
                            "select count(*) from sessions where status='ACTIVE' and expires_at>clock_timestamp() and last_refresh_at>clock_timestamp()-interval '7 days'"))
                    .description("Currently active and unexpired sessions").register(registry);
            Gauge.builder("auth.email.queue.oldest.seconds", jdbc, db -> query(db, registry,
                            "select coalesce(greatest(0,extract(epoch from clock_timestamp()-min(created_at))),0) from notification_outbox where status='PENDING'"))
                    .description("Age of the oldest pending email").register(registry);
        };
    }
}
