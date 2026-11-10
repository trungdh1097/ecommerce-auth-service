package com.d10g.ecommerce_auth.adapter.in.web;

import java.util.UUID;

/**
 * Set only after both JWT verification and online session introspection.
 */
public record AuthPrincipal(UUID userId, UUID sessionId) {
}
