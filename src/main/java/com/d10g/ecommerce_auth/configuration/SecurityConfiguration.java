package com.d10g.ecommerce_auth.configuration;

import com.d10g.ecommerce_auth.adapter.in.web.ClientRegistry;
import com.d10g.ecommerce_auth.adapter.in.web.ClientTransportFilter;
import com.d10g.ecommerce_auth.adapter.in.web.OnlineBearerFilter;
import com.d10g.ecommerce_auth.adapter.in.web.SecurityProblemWriter;
import com.d10g.ecommerce_auth.adapter.out.session.RsaAccessTokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.application.role.RoleService;
import com.d10g.ecommerce_auth.application.session.SessionService;

import java.util.Set;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Unknown routes stay denied; native CSRF exemption requires a server registration and no ambient browser credentials.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectProvider<ClientRegistry> registrations,
                                            ObjectProvider<RsaAccessTokens> keys, ObjectProvider<SessionService> sessions,
                                            ObjectProvider<RoleService> roles) throws Exception {
        var cookies = new CookieCsrfTokenRepository();
        cookies.setCookieCustomizer(b -> b.httpOnly(true).secure(true).sameSite("Lax").path("/"));
        RequestMatcher csrf = request -> {
            if (Set.of("GET", "HEAD", "OPTIONS", "TRACE").contains(request.getMethod())) return false;
            if ("/internal/v1/auth/introspect".equals(request.getRequestURI())) return false;
            ClientRegistry registry = registrations.getIfAvailable();
            if (registry != null && request.getHeader("Origin") == null && request.getHeader("Cookie") == null) {
                try {
                    if (registry.registration(request.getHeader("X-Client-Id")).platform() != Platform.WEB)
                        return false;
                } catch (IllegalArgumentException ignored) {
                }
            }
            return true;
        };
        return http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(s -> s.csrfTokenRepository(cookies).requireCsrfProtectionMatcher(csrf)
                        .withObjectPostProcessor(new ObjectPostProcessor<CsrfFilter>() {
                            @Override
                            public <O extends CsrfFilter> O postProcess(O filter) {
                                filter.setAccessDeniedHandler((request, response, exception) -> SecurityProblemWriter.write(response, 403, "CSRF_INVALID"));
                                return filter;
                            }
                        }))
                .exceptionHandling(s -> s.authenticationEntryPoint((request, response, exception) -> SecurityProblemWriter.write(response, 401, "SESSION_REVOKED"))
                        .accessDeniedHandler((request, response, exception) -> SecurityProblemWriter.write(response, 403, "ACCESS_DENIED")))
                .addFilterBefore(new ClientTransportFilter(registrations), CsrfFilter.class)
                .addFilterBefore(new OnlineBearerFilter(keys, sessions, roles), AuthorizationFilter.class)
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.GET, "/.well-known/jwks.json").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health/liveness", "/actuator/health/readiness").permitAll()
                        .requestMatchers(HttpMethod.POST, "/internal/v1/auth/introspect").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/email/verify", "/api/v1/auth/email/resend",
                                "/api/v1/auth/password/forgot", "/api/v1/auth/password/reset", "/api/v1/auth/login",
                                "/api/v1/auth/login/otp/verify", "/api/v1/auth/login/otp/resend", "/api/v1/auth/refresh",
                                "/api/v1/auth/logout", "/api/v1/auth/google/challenge", "/api/v1/auth/google/exchange").permitAll()
                        .requestMatchers("/api/v1/role/*").hasRole("ADMIN")
                        .requestMatchers("/api/v1/auth/google/link", "/api/v1/auth/google/link/challenge").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/password/change").authenticated()
                        .requestMatchers("/api/v1/auth/me", "/api/v1/auth/sessions", "/api/v1/auth/sessions/**", "/api/v1/auth/logout-all").authenticated()
                        .anyRequest().denyAll()).build();
    }
}
