package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.adapter.out.login.RedisPublicLimits;
import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.application.session.SessionPorts.SessionMetadata;
import com.d10g.ecommerce_auth.security.crypto.OpaqueSecrets;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Resolves configured client identity and controls credential transport.
 */
@Component
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class WebAuthSupport {
    public static final String CONTEXT_COOKIE = "AUTH_CONTEXT";
    public static final String REFRESH_COOKIE = "AUTH_REFRESH";
    private static final String REFRESH_PATH = "/api/v1/auth";
    private final ClientRegistry clients;
    private final OpaqueSecrets secrets;
    private final JdbcTemplate db;
    private final RedisPublicLimits limits;
    private final Duration trustedDeviceTtl;

    public WebAuthSupport(ClientRegistry clients, OpaqueSecrets secrets, JdbcTemplate db, RedisPublicLimits limits) {
        this(clients, secrets, db, limits, Duration.ofDays(90));
    }

    public WebAuthSupport(ClientRegistry clients, OpaqueSecrets secrets, JdbcTemplate db, RedisPublicLimits limits,
                          Duration trustedDeviceTtl) {
        this.clients = clients;
        this.secrets = secrets;
        this.db = db;
        this.limits = limits;
        if (trustedDeviceTtl == null || trustedDeviceTtl.isZero() || trustedDeviceTtl.isNegative())
            throw new IllegalArgumentException("trusted-device-ttl must be positive");
        this.trustedDeviceTtl = trustedDeviceTtl;
    }

    @Autowired
    public WebAuthSupport(ClientRegistry clients, OpaqueSecrets secrets, JdbcTemplate db, RedisPublicLimits limits,
                          @Value("${auth.runtime.trusted-device-ttl:P90D}") String trustedDeviceTtl) {
        this(clients, secrets, db, limits, Duration.parse(trustedDeviceTtl));
    }

    private static SessionMetadata metadata(HttpServletRequest req, String label) {
        return new SessionMetadata(clean(label, 100), clean(req.getHeader("User-Agent"), 256), maskIp(req.getRemoteAddr()));
    }

    private static String clean(String value, int max) {
        if (value == null) return null;
        StringBuilder out = new StringBuilder();
        value.codePoints().filter(cp -> !Character.isISOControl(cp) && Character.getType(cp) != Character.FORMAT && cp != '<' && cp != '>')
                .limit(max).forEach(out::appendCodePoint);
        String cleaned = out.toString().trim();
        return cleaned.isEmpty() ? null : cleaned;
    }

    private static String maskIp(String ip) {
        if (ip == null || !ip.matches("[0-9a-fA-F:.]+")) return null;
        try {
            byte[] bytes = java.net.InetAddress.getByName(ip).getAddress();
            if (bytes.length == 4) return (bytes[0] & 255) + "." + (bytes[1] & 255) + "." + (bytes[2] & 255) + ".x";
            if (bytes.length == 16)
                return String.format(java.util.Locale.ROOT, "%02x%02x:%02x%02x:%02x%02x::/48", bytes[0] & 255, bytes[1] & 255, bytes[2] & 255, bytes[3] & 255, bytes[4] & 255, bytes[5] & 255);
        } catch (java.net.UnknownHostException ignored) {
        }
        return null;
    }

    private static String cookie(HttpServletRequest req, String name) {
        String value = null;
        if (req.getCookies() != null) for (Cookie cookie : req.getCookies())
            if (Objects.equals(cookie.getName(), name)) {
                if (value != null) throw new ApiProblemException(400, "INVALID_REQUEST");
                value = cookie.getValue();
            }
        return value;
    }

    public Client client(HttpServletRequest req, String bodyClientId) {
        return client(req, bodyClientId, null);
    }

    public Client client(HttpServletRequest req, String bodyClientId, String deviceLabel) {
        String id = req.getHeader("X-Client-Id");
        if (id == null || (bodyClientId != null && !id.equals(bodyClientId)))
            throw new ApiProblemException(400, "INVALID_REQUEST");
        var registration = clients.registration(id);
        if (registration.platform() == Platform.WEB) {
            String context = cookie(req, CONTEXT_COOKIE);
            if (context == null || !validContext(context)) throw new ApiProblemException(400, "CHALLENGE_INVALID");
            return new Client(id, Platform.WEB, secrets.sha256(context), metadata(req, deviceLabel));
        }
        if (req.getHeader("Origin") != null || req.getHeader("Cookie") != null)
            throw new ApiProblemException(403, "INVALID_CLIENT");
        return new Client(id, registration.platform(), null, metadata(req, deviceLabel));
    }

    public void checkIp(HttpServletRequest req) {
        limits.checkIp(req.getRemoteAddr());
    }

    public void checkEmail(String email, HttpServletRequest req) {
        limits.checkEmailRequest(email, req.getRemoteAddr());
    }

    public void requireWeb(HttpServletRequest req) {
        if (clients.registration(req.getHeader("X-Client-Id")).platform() != Platform.WEB)
            throw new ApiProblemException(403, "INVALID_CLIENT");
    }

    public String context(HttpServletRequest req) {
        String existing = cookie(req, CONTEXT_COOKIE);
        if (existing != null && validContext(existing)) return existing;
        String value = secrets.generate();
        db.update("insert into browser_contexts(id,secret_hash,created_at,last_seen_at) values(?,?,clock_timestamp(),clock_timestamp())", UUID.randomUUID(), secrets.sha256(value));
        return value;
    }

    public ResponseCookie contextCookie(String value) {
        return ResponseCookie.from(CONTEXT_COOKIE, value).secure(true).httpOnly(true).sameSite("Lax").path("/").maxAge(trustedDeviceTtl).build();
    }

    public String refresh(HttpServletRequest req, Client client, String bodyToken) {
        if (client.platform() == Platform.WEB) {
            if (bodyToken != null) throw new ApiProblemException(400, "INVALID_REQUEST");
            return cookie(req, REFRESH_COOKIE);
        }
        return bodyToken;
    }

    public ResponseCookie refreshCookie(String value) {
        return ResponseCookie.from(REFRESH_COOKIE, value).secure(true).httpOnly(true).sameSite("Lax").path(REFRESH_PATH).maxAge(Duration.ofDays(30)).build();
    }

    public ResponseCookie clearRefreshCookie() {
        return ResponseCookie.from(REFRESH_COOKIE, "").secure(true).httpOnly(true).sameSite("Lax").path(REFRESH_PATH).maxAge(Duration.ZERO).build();
    }

    public ResponseEntity<Map<String, Object>> tokenResponse(Client client, Tokens tokens) {
        return tokenResponse(client, tokens, null);
    }

    public ResponseEntity<Map<String, Object>> tokenResponse(Client client, Tokens tokens, String deviceSecret) {
        return tokenResponse(client, tokens, deviceSecret, null);
    }

    public ResponseEntity<Map<String, Object>> tokenResponse(Client client, Tokens tokens, String deviceSecret, HttpServletRequest verifiedOtpRequest) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("access_token", tokens.accessToken());
        result.put("token_type", "Bearer");
        result.put("expires_in", tokens.expiresIn());
        result.put("session_id", tokens.sessionId());
        var builder = ResponseEntity.ok().cacheControl(CacheControl.noStore());
        if (client.platform() == Platform.WEB) {
            builder.header(HttpHeaders.SET_COOKIE, refreshCookie(tokens.refreshToken()).toString());
            if (verifiedOtpRequest != null)
                builder.header(HttpHeaders.SET_COOKIE, contextCookie(cookie(verifiedOtpRequest, CONTEXT_COOKIE)).toString());
        } else {
            result.put("refresh_token", tokens.refreshToken());
            if (deviceSecret != null) result.put("device_secret", deviceSecret);
        }
        return builder.body(result);
    }

    private boolean validContext(String value) {
        if (value.length() != 43) return false;
        return Boolean.TRUE.equals(db.queryForObject("select exists(select 1 from browser_contexts where secret_hash=?)", Boolean.class, secrets.sha256(value)));
    }
}
