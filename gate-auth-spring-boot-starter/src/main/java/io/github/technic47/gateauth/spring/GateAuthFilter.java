package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateUser;
import io.github.technic47.gateauth.core.TokenValidationException;
import io.github.technic47.gateauth.core.TokenVerifier;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Spec §8 steps 1–2: ends over-age sessions, then authenticates an edge request from its assertion header.
 *
 * An invalid assertion is answered with 401 right here and never falls through to the session.
 * Edge requests get a request-scoped security context only; no session is created.
 */
final class GateAuthFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(GateAuthFilter.class);

    private final GateAuthSettings settings;
    private final TokenVerifier verifier;
    private final GateSessions sessions;
    private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();

    GateAuthFilter(GateAuthSettings settings, TokenVerifier verifier, GateSessions sessions) {
        this.settings = settings;
        this.verifier = verifier;
        this.sessions = sessions;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (sessions.expireIfOld(request)) {
            log.info("gate-auth: session reached its absolute lifetime and was ended");
        }

        String assertion = settings.edgeEnabled() ? request.getHeader(settings.props().edge().header()) : null;
        if (assertion == null || assertion.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }

        GateClaims claims;
        try {
            claims = verifier.verifyAssertion(assertion);
        } catch (TokenValidationException e) {
            log.warn("gate-auth: edge assertion rejected: {} uri={}", e.getMessage(), GateAuthSettings.path(request));
            if (settings.isApi(request) || !Http.wantsHtml(request)) {
                Http.problem(response, 401, "Unauthorized", null);
            } else {
                Http.page(response, 401, "Not signed in", "<p>The gate's signature on this request is invalid or expired. "
                        + "Reload the page.</p>");
            }
            return;
        }

        SecurityContext context = holder.createEmptyContext();
        context.setAuthentication(new GateAuthentication(GateUser.from(claims, AuthMode.EDGE), settings.adminImpliesRoles()));
        holder.setContext(context);
        try {
            chain.doFilter(request, response);
        } finally {
            holder.clearContext();
        }
    }
}
