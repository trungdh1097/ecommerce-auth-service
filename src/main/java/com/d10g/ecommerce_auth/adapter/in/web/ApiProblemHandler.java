package com.d10g.ecommerce_auth.adapter.in.web;

import com.d10g.ecommerce_auth.adapter.out.login.RedisLoginLimits;
import com.d10g.ecommerce_auth.adapter.out.google.GoogleKeysUnavailableException;
import com.d10g.ecommerce_auth.application.observability.AuthMetrics;

import java.util.Locale;

import org.slf4j.MDC;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

@RestControllerAdvice
public final class ApiProblemHandler {
    private AuthMetrics metrics = AuthMetrics.NOOP;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setMetrics(AuthMetrics metrics) {
        this.metrics = metrics;
    }

    @ExceptionHandler(ApiProblemException.class)
    ResponseEntity<ProblemDetail> business(ApiProblemException ex) {
        return problem(ex.status(), ex.code(), ex.retryAfterSeconds());
    }

    @ExceptionHandler(RedisLoginLimits.RateLimitedException.class)
    ResponseEntity<ProblemDetail> limited(RedisLoginLimits.RateLimitedException ex) {
        metrics.event(AuthMetrics.Event.RATE_LIMIT, AuthMetrics.Outcome.REJECTED);
        return problem(429, "RATE_LIMITED", ex.retryAfterSeconds());
    }

    @ExceptionHandler(DataAccessException.class)
    ResponseEntity<ProblemDetail> dependency(DataAccessException ex) {
        return problem(503, "DEPENDENCY_UNAVAILABLE", 0);
    }

    @ExceptionHandler(GoogleKeysUnavailableException.class)
    ResponseEntity<ProblemDetail> googleKeys(GoogleKeysUnavailableException ex) {
        return problem(503, "DEPENDENCY_UNAVAILABLE", 0);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<ProblemDetail> invalid(IllegalArgumentException ex) {
        return problem(400, "INVALID_REQUEST", 0);
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    ResponseEntity<ProblemDetail> invalidInput(Exception ex) {
        return problem(400, "INVALID_REQUEST", 0);
    }

    private ResponseEntity<ProblemDetail> problem(int status, String code, long retry) {
        ProblemDetail detail = ProblemDetail.forStatus(HttpStatusCode.valueOf(status));
        detail.setTitle(code.replace('_', ' ').toLowerCase(Locale.ROOT));
        detail.setProperty("code", code);
        String trace = MDC.get("traceId");
        if (trace != null && trace.matches("[0-9a-fA-F]{16,32}")) detail.setProperty("traceId", trace);
        else detail.setProperty("traceId", java.util.UUID.randomUUID().toString().replace("-", ""));
        if ("REGISTRATION_PENDING".equals(code) && retry > 0) detail.setProperty("retry_after_seconds", retry);
        var builder = ResponseEntity.status(status).header(HttpHeaders.CACHE_CONTROL, "no-store");
        if (retry > 0) builder.header(HttpHeaders.RETRY_AFTER, Long.toString(retry));
        return builder.body(detail);
    }
}
