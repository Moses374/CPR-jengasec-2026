package com.cpr.payments.observability;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Lets any code on the request path name the security event for the current request.
 * The {@link RequestLogFilter} writes it into the request's log line.
 *
 * <pre>
 *   AuditContext.action("transfer.denied");
 * </pre>
 *
 * Use short dotted names: login.failed, transfer.created, transfer.denied, authz.denied ...
 * The last call wins, so set the most specific outcome.
 */
public final class AuditContext {

    static final String ACTION_ATTR = AuditContext.class.getName() + ".action";
    static final String USER_ATTR = AuditContext.class.getName() + ".user";

    private AuditContext() {
    }

    public static void action(String action) {
        HttpServletRequest request = currentRequest();
        if (request != null) {
            request.setAttribute(ACTION_ATTR, action);
        }
    }

    /** Records the authenticated user id. Call once authentication succeeds. */
    public static void user(String userId) {
        HttpServletRequest request = currentRequest();
        if (request != null) {
            request.setAttribute(USER_ATTR, userId);
        }
    }

    private static HttpServletRequest currentRequest() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        return attrs instanceof ServletRequestAttributes sra ? sra.getRequest() : null;
    }
}
