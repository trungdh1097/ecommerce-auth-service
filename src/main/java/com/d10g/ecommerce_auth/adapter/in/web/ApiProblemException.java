package com.d10g.ecommerce_auth.adapter.in.web;

/**
 * Transport-neutral code is supplied by the application adapter, never raw exception text.
 */
public final class ApiProblemException extends RuntimeException {
    private final int status;
    private final String code;
    private final long retryAfterSeconds;

    public ApiProblemException(int status, String code) {
        this(status, code, 0);
    }

    public ApiProblemException(int status, String code, long retryAfterSeconds) {
        super(code);
        this.status = status;
        this.code = code;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
