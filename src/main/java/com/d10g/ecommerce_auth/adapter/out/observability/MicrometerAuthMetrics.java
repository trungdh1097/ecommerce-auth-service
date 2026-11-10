package com.d10g.ecommerce_auth.adapter.out.observability;

import com.d10g.ecommerce_auth.application.observability.AuthMetrics;
import io.micrometer.core.instrument.MeterRegistry;

import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Metrics use enum-derived labels only; credentials and identifiers never enter labels.
 */
public final class MicrometerAuthMetrics implements AuthMetrics {
    private final MeterRegistry registry;

    public MicrometerAuthMetrics(MeterRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    @Override
    public void event(Event event, Outcome outcome) {
        registry.counter("auth.events", "event", event.name().toLowerCase(Locale.ROOT),
                "outcome", outcome.name().toLowerCase(Locale.ROOT)).increment();
    }

    @Override
    public void introspection(long elapsedNanos, boolean error) {
        registry.timer("auth.introspection", "outcome", error ? "error" : "completed")
                .record(Math.max(0, elapsedNanos), TimeUnit.NANOSECONDS);
    }
}
