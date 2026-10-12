package com.cpr.payments.observability;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Writes exactly one JSON line per request to stdout, following the JengaSec logging contract:
 * ts, src_ip, method, path, status, user, action.
 *
 * Runs outermost (before Spring Security) so requests rejected by security are logged too.
 * The query string is deliberately not logged, so tokens or secrets in URLs never reach the logs.
 * Jackson escapes every value, so attacker-controlled text cannot break the line format.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestLogFilter extends OncePerRequestFilter {

    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("SECURITY");

    private final ObjectMapper mapper;

    public RequestLogFilter(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        // An exception escaping the chain becomes a 500 via the container's error page, but the
        // response status is not set yet at this point, so record it explicitly.
        int status = -1;
        try {
            chain.doFilter(request, response);
        } catch (IOException | ServletException | RuntimeException e) {
            status = 500;
            throw e;
        } finally {
            write(request, status == -1 ? response.getStatus() : status);
        }
    }

    private void write(HttpServletRequest request, int status) {
        ObjectNode line = mapper.createObjectNode();
        line.put("ts", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
        line.put("src_ip", request.getRemoteAddr());
        line.put("method", request.getMethod());
        line.put("path", request.getRequestURI());
        line.put("status", status);
        line.put("user", resolveUser(request));
        line.put("action", resolveAction(request, status));
        SECURITY_LOG.info(line.toString());
    }

    // Spring Security clears its context before control returns to this outer filter, so the
    // authentication code must record the user with AuditContext.user(...). The context lookup
    // is only a fallback.
    private static String resolveUser(HttpServletRequest request) {
        Object explicit = request.getAttribute(AuditContext.USER_ATTR);
        if (explicit != null) {
            return explicit.toString();
        }
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getName())) {
            return auth.getName();
        }
        return "";
    }

    private static String resolveAction(HttpServletRequest request, int status) {
        Object explicit = request.getAttribute(AuditContext.ACTION_ATTR);
        if (explicit != null) {
            return explicit.toString();
        }
        String path = request.getRequestURI();
        if ("/healthz".equals(path) || "/readyz".equals(path)) {
            return "health.check";
        }
        return switch (status) {
            case 401 -> "auth.unauthenticated";
            case 403 -> "authz.denied";
            case 404 -> "http.not_found";
            case 405 -> "http.method_not_allowed";
            case 429 -> "ratelimit.hit";
            default -> status >= 500 ? "http.error" : status >= 400 ? "input.rejected" : "http.request";
        };
    }
}
