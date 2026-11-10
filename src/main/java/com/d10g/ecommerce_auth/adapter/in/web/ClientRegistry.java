package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;

import java.net.URI;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Server-owned registrations; client IDs identify transport but are not secrets.
 */
public final class ClientRegistry {
    private final Map<String, Registration> registrations;
    private final Set<String> allowedOrigins;
    public ClientRegistry(Map<String, Registration> registrations, Set<String> allowedOrigins) {
        this.registrations = Map.copyOf(registrations);
        this.allowedOrigins = Set.copyOf(allowedOrigins);
        if (this.registrations.isEmpty())
            throw new IllegalArgumentException("At least one client registration is required");
        for (String origin : this.allowedOrigins) {
            URI uri = URI.create(origin);
            if ((!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme()))
                    || uri.getHost() == null || uri.getUserInfo() != null || uri.getQuery() != null
                    || uri.getFragment() != null || (uri.getRawPath() != null && !uri.getRawPath().isEmpty())) {
                throw new IllegalArgumentException("Origin must contain only scheme, host and optional port");
            }
        }
        if (this.registrations.values().stream().anyMatch(registration -> registration.platform() == Platform.WEB)
                && this.allowedOrigins.isEmpty())
            throw new IllegalArgumentException("WEB requires an origin allowlist");
    }

    public Registration registration(String clientId) {
        Registration registration = clientId == null ? null : registrations.get(clientId);
        if (registration == null) throw new IllegalArgumentException("Unknown client registration");
        return registration;
    }

    /**
     * Validates mutation transport after looking up the registration on the server.
     */
    public Registration validateMutation(String clientId, String origin, boolean hasCookies) {
        Registration registration = registration(clientId);
        if (registration.platform() == Platform.WEB) {
            if (origin == null || !allowedOrigins.contains(origin))
                throw new IllegalArgumentException("Origin rejected");
        } else if (origin != null || hasCookies) {
            throw new IllegalArgumentException("Native client cannot use browser credentials");
        }
        return registration;
    }

    public record Registration(Platform platform, String googleAudience, Set<String> googlePresenters) {
        public Registration {
            Objects.requireNonNull(platform);
            googlePresenters = googlePresenters == null ? Set.of() : Set.copyOf(googlePresenters);
        }
    }
}
