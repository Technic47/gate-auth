package io.github.technic47.gateauth.spring;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Spec §9: state-changing requests must come from one of the app's own origins.
 *
 * All apps on one IP are the same "site", so SameSite cookies don't stop another app (other port) from
 * sending requests here with the gate's cookie. This check plus the CSRF token does.
 * The direct-mode callback is exempt: it is a cross-site POST from the gate, protected by {@code state}.
 */
final class OriginCheckFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(OriginCheckFilter.class);
    private static final Set<String> SAFE = Set.of("GET", "HEAD", "OPTIONS", "TRACE");

    private final GateAuthSettings settings;

    OriginCheckFilter(GateAuthSettings settings) {
        this.settings = settings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (SAFE.contains(request.getMethod()) || isCallback(request)) {
            chain.doFilter(request, response);
            return;
        }
        String origin = request.getHeader("Origin");
        if (origin == null || "null".equals(origin)) {
            origin = refererOrigin(request.getHeader("Referer"));
        }
        if (!settings.isAllowedOrigin(origin)) {
            log.warn("gate-auth: blocked {} {} from origin {}", request.getMethod(), GateAuthSettings.path(request), origin);
            Http.problem(response, 403, "Forbidden", null);
            return;
        }
        chain.doFilter(request, response);
    }

    private boolean isCallback(HttpServletRequest request) {
        return settings.directEnabled() && "POST".equals(request.getMethod())
                && GateAuthSettings.path(request).equals(settings.callbackPath());
    }

    private static String refererOrigin(String referer) {
        if (referer == null) {
            return null;
        }
        int schemeEnd = referer.indexOf("://");
        if (schemeEnd < 0) {
            return null;
        }
        int pathStart = referer.indexOf('/', schemeEnd + 3);
        return pathStart < 0 ? referer : referer.substring(0, pathStart);
    }
}
