package com.d10g.ecommerce_auth.application.observability;

/**
 * Technology-neutral, low-cardinality authentication telemetry. Never accepts user input.
 */
public interface AuthMetrics {
    AuthMetrics NOOP = new AuthMetrics() {
        public void event(Event event, Outcome outcome) {
        }

        public void introspection(long elapsedNanos, boolean error) {
        }
    };

    void event(Event event, Outcome outcome);

    void introspection(long elapsedNanos, boolean error);

    enum Event {LOGIN, OTP, REFRESH_REUSE, RATE_LIMIT}

    enum Outcome {SUCCESS, FAILURE, ERROR, REJECTED}
}
