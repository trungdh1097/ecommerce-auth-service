package com.d10g.ecommerce_auth.adapter.out.maintenance;

import com.d10g.ecommerce_auth.application.audit.AuditPort;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;

import java.util.Objects;
import java.util.UUID;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Writes audit as part of the caller's transaction; raw session IDs are never stored.
 */
public final class JdbcAuditRecorder implements AuditPort {
    private final JdbcTemplate db;
    private final OpaqueSecrets secrets;

    public JdbcAuditRecorder(JdbcTemplate db, OpaqueSecrets secrets) {
        this.db = Objects.requireNonNull(db);
        this.secrets = Objects.requireNonNull(secrets);
    }

    @Override
    public void record(EventType event, UUID userId, UUID sessionId, Outcome outcome, String traceId) {
        Objects.requireNonNull(event);
        Objects.requireNonNull(outcome);
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Audit event requires an active transaction");
        }
        if (traceId == null) {
            String contextualTrace = org.slf4j.MDC.get("traceId");
            if (contextualTrace != null && contextualTrace.matches("[0-9a-fA-F]{16,32}")) traceId = contextualTrace;
        }
        if (traceId != null && !traceId.matches("[0-9a-fA-F]{16,32}")) {
            throw new IllegalArgumentException("Invalid trace ID");
        }
        byte[] correlation = sessionId == null ? null : secrets.sha256(sessionId.toString());
        db.update("insert into audit_events(id,event_type,user_id,session_correlation_hash,result,trace_id,created_at) values (?,?,?,?,?,?,clock_timestamp())",
                UUID.randomUUID(), event.name(), userId, correlation, outcome.name(), traceId);
    }
}
