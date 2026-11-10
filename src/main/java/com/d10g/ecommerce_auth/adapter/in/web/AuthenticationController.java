package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.application.account.AccountService;
import com.d10g.ecommerce_auth.application.login.LoginPorts.Tokens;
import com.d10g.ecommerce_auth.application.login.LoginService;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Platform;
import com.d10g.ecommerce_auth.application.session.SessionService;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class AuthenticationController {
    private final AccountService accounts;
    private final LoginService login;
    private final SessionService sessions;
    private final WebAuthSupport transport;

    public AuthenticationController(AccountService accounts, LoginService login, SessionService sessions, WebAuthSupport transport) {
        this.accounts = accounts;
        this.login = login;
        this.sessions = sessions;
        this.transport = transport;
    }

    private static ApiProblemException loginError(LoginService.Status status) {
        return switch (status) {
            case INVALID_CREDENTIALS -> new ApiProblemException(401, "INVALID_CREDENTIALS");
            case EMAIL_VERIFICATION_REQUIRED -> new ApiProblemException(403, "EMAIL_VERIFICATION_REQUIRED");
            case OTP_INVALID -> new ApiProblemException(400, "OTP_INVALID");
            case CHALLENGE_EXPIRED -> new ApiProblemException(400, "CHALLENGE_EXPIRED");
            case RESEND_TOO_SOON -> new ApiProblemException(429, "RATE_LIMITED", 60);
            default -> new ApiProblemException(400, "CHALLENGE_INVALID");
        };
    }

    private static ApiProblemException sessionError(SessionService.Status status) {
        return switch (status) {
            case SESSION_CONTEXT_CHANGED -> new ApiProblemException(409, "SESSION_CONTEXT_CHANGED");
            case REFRESH_REUSED -> new ApiProblemException(401, "REFRESH_REUSED");
            default -> new ApiProblemException(401, "SESSION_REVOKED");
        };
    }

    private static ResponseEntity<Void> accepted() {
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore()).build();
    }

    private static ResponseEntity<Void> noContent() {
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    @GetMapping("/csrf")
    public ResponseEntity<Map<String, String>> csrf(HttpServletRequest request, CsrfToken token) {
        transport.requireWeb(request);
        transport.checkIp(request);
        String context = transport.context(request);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .header(HttpHeaders.SET_COOKIE, transport.contextCookie(context).toString())
                .body(Map.of("header_name", token.getHeaderName(), "token", token.getToken()));
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody Register body, HttpServletRequest req) {
        transport.checkIp(req);
        if (accounts.register(body.username(), body.email(), body.password()) == AccountService.Result.USERNAME_UNAVAILABLE)
            throw new ApiProblemException(409, "USERNAME_UNAVAILABLE");
        return accepted();
    }

    @PostMapping("/email/verify")
    public ResponseEntity<Void> verifyEmail(@Valid @RequestBody Token body, HttpServletRequest req) {
        transport.checkIp(req);
        if (accounts.verifyEmail(body.token()) != AccountService.Result.OK)
            throw new ApiProblemException(400, "CHALLENGE_INVALID");
        return noContent();
    }

    @PostMapping("/email/resend")
    public ResponseEntity<Void> resendEmail(@Valid @RequestBody Email body, HttpServletRequest req) {
        transport.checkEmail(body.email(), req);
        accounts.resendVerification(body.email());
        return accepted();
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<Void> forgot(@Valid @RequestBody Email body, HttpServletRequest req) {
        transport.checkEmail(body.email(), req);
        accounts.forgotPassword(body.email());
        return accepted();
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> reset(@Valid @RequestBody Reset body, HttpServletRequest req) {
        transport.checkIp(req);
        if (accounts.resetPassword(body.token(), body.newPassword()) != AccountService.Result.OK)
            throw new ApiProblemException(400, "CHALLENGE_INVALID");
        return noContent();
    }

    @PostMapping("/password/change")
    public ResponseEntity<Void> changePassword(@Valid @RequestBody ChangePassword body,
                                               @org.springframework.security.core.annotation.AuthenticationPrincipal AuthPrincipal principal) {
        if (principal == null) throw new ApiProblemException(401, "SESSION_REVOKED");
        var result = accounts.changePassword(principal.userId(), principal.sessionId(), body.currentPassword(), body.newPassword());
        if (result == AccountService.Result.REAUTHENTICATION_REQUIRED)
            throw new ApiProblemException(403, "REAUTHENTICATION_REQUIRED");
        if (result != AccountService.Result.OK) throw new ApiProblemException(401, "INVALID_CREDENTIALS");
        return noContent();
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@Valid @RequestBody Login body, HttpServletRequest req) {
        Client client = transport.client(req, body.clientId(), body.deviceLabel());
        LoginService.Result result = login.login(body.username(), body.password(), client, req.getRemoteAddr(), body.deviceId(), body.deviceSecret(), Boolean.TRUE.equals(body.requireOtp()));
        return result.status() == LoginService.Status.SUCCESS ? transport.tokenResponse(client, result.tokens()) : challenge(result);
    }

    @PostMapping("/login/otp/verify")
    public ResponseEntity<Map<String, Object>> verifyOtp(@Valid @RequestBody Otp body, HttpServletRequest req) {
        Client client = transport.client(req, body.clientId());
        transport.checkIp(req);
        LoginService.Result result = login.verify(body.challengeId(), client, body.continuationSecret(), body.otp());
        if (result.status() != LoginService.Status.SUCCESS) throw loginError(result.status());
        return transport.tokenResponse(client, result.tokens(), result.deviceSecret(), req);
    }

    @PostMapping("/login/otp/resend")
    public ResponseEntity<Map<String, Object>> resendOtp(@Valid @RequestBody Otp body, HttpServletRequest req) {
        Client client = transport.client(req, body.clientId());
        transport.checkIp(req);
        return challenge(login.resend(body.challengeId(), client, body.continuationSecret()));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, Object>> refresh(@Valid @RequestBody Refresh body, HttpServletRequest req) {
        Client client = transport.client(req, body.clientId());
        SessionService.Result result = sessions.refresh(transport.refresh(req, client, body.refreshToken()), client, body.expectedSessionId());
        if (result.status() != SessionService.Status.SUCCESS) throw sessionError(result.status());
        return transport.tokenResponse(client, new Tokens(result.accessToken(), result.refreshToken(), result.sessionId(), result.expiresIn()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody Refresh body, HttpServletRequest req) {
        Client client = transport.client(req, body.clientId());
        SessionService.Status result = sessions.logout(transport.refresh(req, client, body.refreshToken()), client, body.expectedSessionId());
        if (result == SessionService.Status.SESSION_CONTEXT_CHANGED) throw sessionError(result);
        if (result == SessionService.Status.INVALID) throw new ApiProblemException(401, "SESSION_REVOKED");
        var response = ResponseEntity.noContent().cacheControl(CacheControl.noStore());
        if (client.platform() == Platform.WEB)
            response.header(HttpHeaders.SET_COOKIE, transport.clearRefreshCookie().toString());
        return response.build();
    }

    private ResponseEntity<Map<String, Object>> challenge(LoginService.Result result) {
        if (result.status() != LoginService.Status.ACCEPTED) throw loginError(result.status());
        var data = new LinkedHashMap<String, Object>();
        data.put("challenge_id", result.challengeId());
        data.put("expires_in", Math.max(0, Duration.between(Instant.now(), result.expiresAt()).toSeconds()));
        data.put("resend_after_seconds", Math.max(0, Duration.between(Instant.now(), result.resendAt()).toSeconds()));
        data.put("masked_email", result.maskedEmail());
        if (result.nativeBinding() != null) data.put("continuation_secret", result.nativeBinding());
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore()).body(data);
    }

    public record Register(@NotBlank @Size(max = 50) String username, @NotBlank @Size(max = 320) String email,
                           @NotNull @Size(max = 128) String password) {
    }

    public record Email(@NotBlank @Size(max = 320) String email) {
    }

    public record Token(@NotBlank @Size(max = 256) String token) {
    }

    public record Reset(@NotBlank @Size(max = 256) String token,
                        @NotNull @Size(max = 128) @JsonProperty("new_password") String newPassword) {
    }

    public record Login(@NotBlank @Size(max = 50) String username, @NotNull @Size(max = 128) String password,
                        @NotBlank @Size(max = 100) @JsonProperty("client_id") String clientId,
                        @Size(max = 100) @JsonProperty("device_label") String deviceLabel,
                        @Size(min = 1, max = 255) @Pattern(regexp = "(?s).*\\S.*") @JsonProperty("device_id") String deviceId,
                        @Size(min = 1, max = 256) @JsonProperty("device_secret") String deviceSecret,
                        @JsonProperty("require_otp") Boolean requireOtp) {
    }

    public record Otp(@NotBlank @Size(max = 100) @JsonProperty("client_id") String clientId,
                      @NotNull @JsonProperty("challenge_id") UUID challengeId,
                      @Size(max = 256) @JsonProperty("continuation_secret") String continuationSecret,
                      @Size(max = 6) String otp) {
    }

    public record Refresh(@NotBlank @Size(max = 100) @JsonProperty("client_id") String clientId,
                          @JsonProperty("expected_session_id") UUID expectedSessionId,
                          @Size(max = 256) @JsonProperty("refresh_token") String refreshToken) {
    }

    public record ChangePassword(@NotNull @Size(max = 128) @JsonProperty("current_password") String currentPassword,
                                 @NotNull @Size(max = 128) @JsonProperty("new_password") String newPassword) {
    }
}
