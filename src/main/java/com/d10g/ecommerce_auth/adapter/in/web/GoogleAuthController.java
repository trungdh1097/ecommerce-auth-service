package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.application.google.GoogleFlow;
import com.d10g.ecommerce_auth.application.session.SessionPorts.Client;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Google identity proof is exchanged only through registered clients and a bound challenge.
 */
@RestController
@RequestMapping("/api/v1/auth/google")
@ConditionalOnProperty(prefix = "auth.runtime", name = "enabled", havingValue = "true")
public class GoogleAuthController {
    private final GoogleFlow flow;
    private final WebAuthSupport support;

    public GoogleAuthController(GoogleFlow flow, WebAuthSupport support) {
        this.flow = flow;
        this.support = support;
    }

    private static ResponseEntity<ChallengeResponse> challengeResponse(GoogleFlow.Challenge result) {
        check(result.status(), 0);
        long remaining = Math.max(0, Duration.between(Instant.now(), result.expiresAt()).toSeconds());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(
                new ChallengeResponse(result.id(), result.nonce(), result.nativeBinding(), remaining));
    }

    private static GoogleFlow.Principal requirePrincipal(AuthPrincipal principal) {
        if (principal == null) throw new ApiProblemException(401, "SESSION_REVOKED");
        return new GoogleFlow.Principal(principal.userId(), principal.sessionId());
    }

    private static void check(GoogleFlow.Status status, long retryAfterSeconds) {
        switch (status) {
            case SUCCESS -> {
            }
            case INVALID -> throw new ApiProblemException(400, "CHALLENGE_INVALID");
            case EXPIRED -> throw new ApiProblemException(400, "CHALLENGE_EXPIRED");
            case REAUTHENTICATION_REQUIRED -> throw new ApiProblemException(403, "REAUTHENTICATION_REQUIRED");
            case ACCOUNT_LINK_REQUIRED -> throw new ApiProblemException(409, "ACCOUNT_LINK_REQUIRED");
            case IDENTITY_CONFLICT -> throw new ApiProblemException(409, "IDENTITY_ALREADY_LINKED");
            case REGISTRATION_PENDING -> throw new ApiProblemException(409, "REGISTRATION_PENDING", retryAfterSeconds);
        }
    }

    @PostMapping("/challenge")
    public ResponseEntity<ChallengeResponse> challenge(@Valid @RequestBody ChallengeRequest body, HttpServletRequest request) {
        support.checkIp(request);
        Client client = support.client(request, body.clientId(), body.deviceLabel());
        return challengeResponse(flow.challenge(client, null));
    }

    @PostMapping("/link/challenge")
    public ResponseEntity<ChallengeResponse> linkChallenge(@Valid @RequestBody ChallengeRequest body,
                                                           @AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest request) {
        GoogleFlow.Principal user = requirePrincipal(principal);
        support.checkIp(request);
        Client client = support.client(request, body.clientId(), body.deviceLabel());
        return challengeResponse(flow.challenge(client, user));
    }

    @PostMapping("/exchange")
    public ResponseEntity<?> exchange(@Valid @RequestBody ExchangeRequest body, HttpServletRequest request) {
        support.checkIp(request);
        Client client = support.client(request, body.clientId());
        GoogleFlow.Result result = flow.exchange(client, body.challengeId(), body.binding(), body.googleIdToken());
        check(result.status(), result.retryAfterSeconds());
        return support.tokenResponse(client, result.tokens());
    }

    @PostMapping("/link")
    public ResponseEntity<Void> link(@Valid @RequestBody ExchangeRequest body,
                                     @AuthenticationPrincipal AuthPrincipal principal, HttpServletRequest request) {
        GoogleFlow.Principal user = requirePrincipal(principal);
        support.checkIp(request);
        Client client = support.client(request, body.clientId());
        GoogleFlow.Result result = flow.link(client, user, body.challengeId(), body.binding(), body.googleIdToken());
        check(result.status(), result.retryAfterSeconds());
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    public record ChallengeRequest(@JsonProperty("client_id") @NotBlank @Size(max = 100) String clientId,
                                   @JsonProperty("device_label") @Size(max = 100) String deviceLabel) {
        public ChallengeRequest(String clientId) {
            this(clientId, null);
        }
    }

    public record ExchangeRequest(@JsonProperty("client_id") @NotBlank @Size(max = 100) String clientId,
                                  @JsonProperty("challenge_id") @NotNull UUID challengeId,
                                  @JsonProperty("binding") @Size(max = 256) String binding,
                                  @JsonProperty("google_id_token") @NotBlank @Size(max = 16384) String googleIdToken) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ChallengeResponse(@JsonProperty("challenge_id") UUID challengeId, String nonce,
                                    @JsonProperty("binding") String binding,
                                    @JsonProperty("expires_in") long expiresIn) {
    }
}
