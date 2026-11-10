package com.d10g.ecommerce_auth.adapter.in.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.Set;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects mismatched server registrations and browser origins before CSRF processing.
 */
public final class ClientTransportFilter extends OncePerRequestFilter {
    private static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS", "TRACE");
    private final ObjectProvider<ClientRegistry> registry;

    public ClientTransportFilter(ObjectProvider<ClientRegistry> registry) {
        this.registry = registry;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest r) {
        String path = r.getRequestURI();
        return SAFE.contains(r.getMethod())
                || !(path.startsWith("/api/v1/auth/") || path.startsWith("/api/v1/role/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        ClientRegistry clients = registry.getIfAvailable();
        if (clients == null) {
            SecurityProblemWriter.write(res, 503, "DEPENDENCY_UNAVAILABLE");
            return;
        }
        try {
            clients.validateMutation(req.getHeader("X-Client-Id"), req.getHeader("Origin"), req.getHeader("Cookie") != null);
        } catch (IllegalArgumentException ex) {
            SecurityProblemWriter.write(res, 403, "INVALID_CLIENT");
            return;
        }
        chain.doFilter(req, res);
    }
}
