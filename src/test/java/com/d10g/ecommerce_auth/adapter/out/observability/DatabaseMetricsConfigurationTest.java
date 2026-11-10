package com.d10g.ecommerce_auth.adapter.out.observability;

import static org.junit.jupiter.api.Assertions.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;

class DatabaseMetricsConfigurationTest {
    @Test void gaugesRepresentDatabaseFailureAsUnknown() {
        var registry = new SimpleMeterRegistry();
        var jdbc = new FakeJdbc();
        new DatabaseMetricsConfiguration().authDatabaseGauges(jdbc).bindTo(registry);
        assertEquals(4.0, registry.get("auth.sessions.active").gauge().value());
        assertEquals(12.0, registry.get("auth.email.queue.oldest.seconds").gauge().value());
        jdbc.fail = true;
        assertTrue(Double.isNaN(registry.get("auth.sessions.active").gauge().value()));
        assertEquals(1, registry.get("auth.database.errors").counter().count());
    }
    static class FakeJdbc extends JdbcTemplate {
        boolean fail;
        @Override public <T> T queryForObject(String sql, Class<T> type) {
            if (fail) throw new DataAccessResourceFailureException("unavailable");
            return type.cast(sql.contains("notification_outbox") ? Long.valueOf(12) : Long.valueOf(4));
        }
    }
}
