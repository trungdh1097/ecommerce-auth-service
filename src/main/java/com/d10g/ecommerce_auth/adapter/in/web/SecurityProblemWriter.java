package com.d10g.ecommerce_auth.adapter.in.web;

import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.MDC;

/**
 * Emits stable errors from filters, outside MVC exception handling.
 */
public final class SecurityProblemWriter {
    private SecurityProblemWriter() {
    }

    public static void write(HttpServletResponse response, int status, String code) throws IOException {
        String trace = MDC.get("traceId");
        if (trace == null || !trace.matches("[0-9a-fA-F]{16,32}"))
            trace = UUID.randomUUID().toString().replace("-", "");
        response.setStatus(status);
        response.setContentType("application/problem+json");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write("{\"type\":\"about:blank\",\"title\":\"" + code.replace('_', ' ') + "\",\"status\":" + status
                + ",\"code\":\"" + code + "\",\"traceId\":\"" + trace + "\"}");
    }
}
