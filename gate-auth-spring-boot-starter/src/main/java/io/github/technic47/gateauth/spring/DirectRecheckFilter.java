package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Spec §6.6: once per {@code recheck-after}, a page navigation of a direct-mode user is bounced through the gate
 * with {@code prompt=none}, so blocks and revoked access reach LAN sessions.
 *
 * Skipped when the gate looks unreachable, and not retried before {@code recheck-retry}, so a VPS outage
 * never locks LAN users out.
 */
final class DirectRecheckFilter extends OncePerRequestFilter {

    private final GateAuthSettings settings;
    private final GateSessions sessions;
    private final DirectLogin directLogin;
    private final GateReachability reachability;

    DirectRecheckFilter(GateAuthSettings settings, GateSessions sessions, DirectLogin directLogin,
                        GateReachability reachability) {
        this.settings = settings;
        this.sessions = sessions;
        this.directLogin = directLogin;
        this.reachability = reachability;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (due(request)) {
            sessions.setAttribute(request, GateSessions.RECHECK_ATTEMPT, sessions.now());
            if (reachability.isReachable()) {
                String query = request.getQueryString();
                String ret = GateAuthSettings.path(request) + (query == null ? "" : "?" + query);
                directLogin.start(request, response, ret, true);
                return;
            }
        }
        chain.doFilter(request, response);
    }

    private boolean due(HttpServletRequest request) {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (!(a instanceof GateAuthentication ga) || ga.getPrincipal().mode() != AuthMode.DIRECT) {
            return false;
        }
        if (!Http.isNavigation(request) || settings.isApi(request) || settings.isAuthEndpoint(request)) {
            return false;
        }
        long now = sessions.now();
        Long lastChecked = sessions.attribute(request, GateSessions.LAST_CHECKED);
        if (lastChecked == null || now - lastChecked < settings.props().direct().recheckAfter().toSeconds()) {
            return false;
        }
        Long attempt = sessions.attribute(request, GateSessions.RECHECK_ATTEMPT);
        return attempt == null || now - attempt >= settings.props().direct().recheckRetry().toSeconds();
    }
}
