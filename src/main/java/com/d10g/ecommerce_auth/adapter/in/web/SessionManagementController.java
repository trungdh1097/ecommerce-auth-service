package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.application.session.SessionManagementService;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Only an online-validated principal can select a user or current session.
 */
@RestController
@RequestMapping("/api/v1/auth")
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class SessionManagementController {
    private final SessionManagementService sessions;

    public SessionManagementController(SessionManagementService sessions) {
        this.sessions = sessions;
    }

    private static AuthPrincipal require(AuthPrincipal principal) {
        if (principal == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        return principal;
    }

    private static String browser(String agent) {
        if (agent == null) return null;
        if (agent.contains("Edg/") || agent.contains("EdgA/") || agent.contains("EdgiOS/")) return "Edge";
        if (agent.contains("Firefox/") || agent.contains("FxiOS/")) return "Firefox";
        if (agent.contains("Chrome/") || agent.contains("CriOS/")) return "Chrome";
        if (agent.contains("Safari/") && agent.contains("Version/")) return "Safari";
        return null;
    }

    private static String operatingSystem(String agent, String platform) {
        if ("ANDROID".equals(platform)) return "Android";
        if ("IOS".equals(platform)) return "iOS";
        if (agent == null) return null;
        if (agent.contains("Android")) return "Android";
        if (agent.contains("iPhone") || agent.contains("iPad") || agent.contains("iPod")) return "iOS";
        if (agent.contains("Windows NT")) return "Windows";
        if (agent.contains("Mac OS X")) return "macOS";
        if (agent.contains("Linux")) return "Linux";
        return null;
    }

    @GetMapping("/me")
    public ResponseEntity<Profile> me(@AuthenticationPrincipal AuthPrincipal principal) {
        var profile = sessions.me(require(principal).userId());
        if (profile == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(
                new Profile(profile.id(), profile.username(), profile.email(), profile.emailVerified(), profile.loginMethods()));
    }

    @GetMapping("/sessions")
    public ResponseEntity<Page> list(@AuthenticationPrincipal AuthPrincipal principal,
                                     @RequestParam(required = false) String cursor, @RequestParam(required = false) Integer limit) {
        var user = require(principal);
        try {
            var page = sessions.sessions(user.userId(), user.sessionId(), cursor, limit);
            var items = page.sessions().stream().map(s -> new Session(s.id(), s.platform(), s.deviceLabel(), s.userAgent(),
                    browser(s.userAgent()), operatingSystem(s.userAgent(), s.platform()),
                    s.maskedIp(), s.createdAt(), s.lastSeenAt(), s.expiresAt(), s.current())).toList();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new Page(items, page.nextCursor()));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid pagination");
        }
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> revoke(@AuthenticationPrincipal AuthPrincipal principal, @PathVariable UUID sessionId) {
        if (sessions.revoke(require(principal).userId(), sessionId) == SessionManagementService.RevokeResult.NOT_FOUND)
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    @PostMapping("/logout-all")
    public ResponseEntity<Void> logoutAll(@AuthenticationPrincipal AuthPrincipal principal) {
        sessions.logoutAll(require(principal).userId());
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    public record Profile(@JsonProperty("user_id") UUID userId, String username, String email,
                          @JsonProperty("email_verified") boolean emailVerified,
                          @JsonProperty("login_methods") List<String> loginMethods) {
    }

    public record Session(@JsonProperty("session_id") UUID sessionId, String platform,
                          @JsonProperty("device_label") String deviceLabel,
                          @JsonProperty("user_agent") String userAgent,
                          String browser, @JsonProperty("operating_system") String operatingSystem,
                          @JsonProperty("masked_ip") String maskedIp, @JsonProperty("created_at") Instant createdAt,
                          @JsonProperty("last_seen_at") Instant lastSeenAt,
                          @JsonProperty("expires_at") Instant expiresAt,
                          @JsonProperty("is_current") boolean current) {
    }

    public record Page(List<Session> sessions, @JsonProperty("next_cursor") String nextCursor) {
    }
}
