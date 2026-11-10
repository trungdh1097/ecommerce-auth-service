package com.d10g.ecommerce_auth.application.session;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * User-scoped session and account queries. Caller must authenticate and introspect the JWT first.
 */
public final class SessionManagementService {
    private final Store store;

    public SessionManagementService(Store store) {
        this.store = Objects.requireNonNull(store);
    }

    private static String encode(SessionItem item) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString((item.createdAt() + "|" + item.id()).getBytes(StandardCharsets.UTF_8));
    }

    private static Cursor decode(String raw) {
        if (raw == null || raw.isBlank()) return null;
        if (raw.length() > 256) throw new IllegalArgumentException("Invalid cursor");
        try {
            String[] parts = new String(Base64.getUrlDecoder().decode(raw), StandardCharsets.UTF_8).split("\\|", -1);
            if (parts.length != 2) throw new IllegalArgumentException("Invalid cursor");
            return new Cursor(Instant.parse(parts[0]), UUID.fromString(parts[1]));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid cursor", e);
        }
    }

    public Profile me(UUID userId) {
        return store.findProfile(Objects.requireNonNull(userId));
    }

    public SessionPage sessions(UUID userId, UUID currentSession, String cursor, Integer limit) {
        int size = limit == null ? 20 : limit;
        if (size < 1 || size > 100) throw new IllegalArgumentException("Invalid page size");
        List<SessionItem> results = store.list(Objects.requireNonNull(userId), Objects.requireNonNull(currentSession), decode(cursor), size + 1);
        boolean more = results.size() > size;
        List<SessionItem> page = List.copyOf(results.subList(0, Math.min(size, results.size())));
        String next = more ? encode(page.get(page.size() - 1)) : null;
        return new SessionPage(page, next);
    }

    public RevokeResult revoke(UUID userId, UUID sessionId) {
        return store.inTransaction(() -> store.revoke(Objects.requireNonNull(userId), Objects.requireNonNull(sessionId)));
    }

    public void logoutAll(UUID userId) {
        store.inTransaction(() -> {
            store.revokeAll(Objects.requireNonNull(userId));
            return null;
        });
    }

    public enum RevokeResult {REVOKED, NOT_FOUND}

    public interface Store {
        <T> T inTransaction(Supplier<T> work);

        Profile findProfile(UUID userId);

        List<SessionItem> list(UUID userId, UUID currentSession, Cursor cursor, int limit);

        RevokeResult revoke(UUID userId, UUID sessionId);

        void revokeAll(UUID userId);
    }

    public record SessionItem(UUID id, String platform, String deviceLabel, String userAgent, String maskedIp,
                              Instant createdAt, Instant lastSeenAt, Instant expiresAt, boolean current) {
    }

    public record SessionPage(List<SessionItem> sessions, String nextCursor) {
        public SessionPage {
            sessions = List.copyOf(sessions);
        }
    }

    public record Profile(UUID id, String username, String email, boolean emailVerified, List<String> loginMethods) {
        public Profile {
            loginMethods = List.copyOf(loginMethods);
        }
    }

    public record Cursor(Instant createdAt, UUID id) {
    }
}
