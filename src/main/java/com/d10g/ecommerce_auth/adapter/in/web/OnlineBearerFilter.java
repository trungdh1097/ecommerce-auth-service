package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.role.RoleService;
import com.d10g.ecommerce_auth.application.session.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * JWT checks and uncached primary-database introspection. Logout/refresh ignore Authorization.
 */
public final class OnlineBearerFilter extends OncePerRequestFilter {
    private final ObjectProvider<RsaAccessTokens> keys;
    private final ObjectProvider<SessionService> sessions;
    private final ObjectProvider<RoleService> roles;

    public OnlineBearerFilter(ObjectProvider<RsaAccessTokens> keys, ObjectProvider<SessionService> sessions,
                              ObjectProvider<RoleService> roles) {
        this.keys = keys;
        this.sessions = sessions;
        this.roles = roles;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String p = request.getRequestURI();
        return !(p.equals("/api/v1/auth/me") || p.equals("/api/v1/auth/sessions") || p.startsWith("/api/v1/auth/sessions/")
                || p.equals("/api/v1/auth/logout-all") || p.equals("/api/v1/auth/password/change")
                || p.equals("/api/v1/auth/google/link") || p.equals("/api/v1/auth/google/link/challenge")
                || p.startsWith("/api/v1/role/"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        String header = req.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ") || header.substring(7).isBlank()) {
            SecurityProblemWriter.write(res, 401, "SESSION_REVOKED");
            return;
        }
        RsaAccessTokens jwt = keys.getIfAvailable();
        SessionService service = sessions.getIfAvailable();
        if (jwt == null || service == null) {
            SecurityProblemWriter.write(res, 503, "DEPENDENCY_UNAVAILABLE");
            return;
        }
        try {
            String token = header.substring(7);
            var verified = jwt.verify(token);
            if (verified == null || !service.introspect(token)) {
                SecurityProblemWriter.write(res, 401, "SESSION_REVOKED");
                return;
            }
            List<GrantedAuthority> authorities = List.of();
            if (req.getRequestURI().startsWith("/api/v1/role/")) {
                RoleService roleService = roles.getIfAvailable();
                if (roleService == null) {
                    SecurityProblemWriter.write(res, 503, "DEPENDENCY_UNAVAILABLE");
                    return;
                }
                if (roleService.hasRole(verified.userId(), "ADMIN"))
                    authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }
            var auth = UsernamePasswordAuthenticationToken.authenticated(new AuthPrincipal(verified.userId(), verified.sessionId()), null, authorities);
            SecurityContextHolder.getContext().setAuthentication(auth);
            chain.doFilter(req, res);
        } catch (org.springframework.dao.DataAccessException ex) {
            SecurityProblemWriter.write(res, 503, "DEPENDENCY_UNAVAILABLE");
        } finally {
            SecurityContextHolder.clearContext();
        }
    }
}
