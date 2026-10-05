package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import io.github.technic47.gateauth.core.Base64Url;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateUser;
import io.github.technic47.gateauth.core.ReplayGuard;
import io.github.technic47.gateauth.core.TokenValidationException;
import io.github.technic47.gateauth.core.TokenVerifier;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * Direct mode (spec §6): send the browser to the gate's {@code /auth/handoff}, receive the form-posted
 * handoff token on the callback, create the app session.
 */
final class DirectLogin {

    private static final Logger log = LoggerFactory.getLogger(DirectLogin.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    private final GateAuthSettings settings;
    private final TokenVerifier verifier;
    private final ReplayGuard replayGuard;
    private final GateSessions sessions;

    DirectLogin(GateAuthSettings settings, TokenVerifier verifier, ReplayGuard replayGuard, GateSessions sessions) {
        this.settings = settings;
        this.verifier = verifier;
        this.replayGuard = replayGuard;
        this.sessions = sessions;
    }

    /** 302 to the gate. {@code silent} = re-check with {@code prompt=none}. */
    void start(HttpServletRequest request, HttpServletResponse response, String returnPath, boolean silent)
            throws IOException {
        Optional<String> origin = settings.requestOrigin(request);
        if (origin.isEmpty()) {
            log.warn("gate-auth: direct login from an origin not in gate.auth.public-urls: {}://{}:{}",
                    request.getScheme(), request.getServerName(), request.getServerPort());
            Http.page(response, 400, "Unknown address",
                    "<p>This address is not configured for login (<code>gate.auth.public-urls</code>).</p>");
            return;
        }
        String redirectUri = origin.get() + Http.contextUrl(request, settings.callbackPath());
        HandoffCookie cookie = new HandoffCookie(random(), random(), GateAuthSettings.safeReturnPath(returnPath),
                sessions.now() + HandoffCookie.LIFETIME_SECONDS, silent);

        Http.setCookie(response, settings.handoffCookieName(), cookie.encode(settings.props().localSecret()),
                Http.contextUrl(request, settings.callbackPath()), HandoffCookie.LIFETIME_SECONDS,
                // The callback is a cross-site POST from the gate: Lax/Strict cookies would not be sent.
                settings.cookieSecure() ? "None" : "Lax", settings.cookieSecure());

        StringBuilder url = new StringBuilder(settings.gateUrl()).append("/auth/handoff")
                .append("?response_type=id_token&response_mode=form_post")
                .append("&client_id=").append(Http.url(settings.appName()))
                .append("&redirect_uri=").append(Http.url(redirectUri))
                .append("&state=").append(cookie.state())
                .append("&nonce=").append(cookie.nonce());
        if (silent) {
            url.append("&prompt=none");
        }
        response.setHeader("Cache-Control", "no-store");
        response.sendRedirect(url.toString());
    }

    /** {@code POST <base>/callback} with form fields {@code id_token | error}, {@code state}. */
    void callback(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cookiePath = Http.contextUrl(request, settings.callbackPath());
        Optional<HandoffCookie> stored = HandoffCookie.decode(
                Http.cookie(request, settings.handoffCookieName()), settings.props().localSecret(), sessions.now());
        // One use: delete it whatever happens next.
        Http.setCookie(response, settings.handoffCookieName(), "", cookiePath, 0,
                settings.cookieSecure() ? "None" : "Lax", settings.cookieSecure());

        String loginLink = "<a class=\"btn\" href=\"" + Http.esc(Http.contextUrl(request, settings.basePath() + "/login"))
                + "\">Try again</a>";
        if (stored.isEmpty()) {
            Http.page(response, 400, "Login expired", "<p>The login took too long or was started in another browser.</p>"
                    + loginLink);
            return;
        }
        HandoffCookie c = stored.get();
        String state = request.getParameter("state");
        if (state == null || !MessageDigest.isEqual(state.getBytes(StandardCharsets.UTF_8),
                c.state().getBytes(StandardCharsets.UTF_8))) {
            log.warn("gate-auth: handoff state mismatch");
            Http.page(response, 400, "Login failed", "<p>Login state did not match.</p>" + loginLink);
            return;
        }

        String error = request.getParameter("error");
        if (error != null) {
            handleError(request, response, c, error, loginLink);
            return;
        }

        GateClaims claims;
        try {
            claims = verifier.verifyHandoff(request.getParameter("id_token"), c.nonce());
        } catch (TokenValidationException e) {
            log.warn("gate-auth: handoff token rejected: {}", e.getMessage());
            Http.page(response, 401, "Login failed", "<p>The gate's answer could not be verified.</p>" + loginLink);
            return;
        }
        if (!replayGuard.firstUse(claims.tokenId(), claims.expiresAt())) {
            log.warn("gate-auth: handoff token replayed (jti={})", claims.tokenId());
            Http.page(response, 401, "Login failed", "<p>This login answer was already used.</p>" + loginLink);
            return;
        }

        GateUser user = GateUser.from(claims, AuthMode.DIRECT);
        GateUser current = currentDirectUser();
        if (c.recheck() && current != null && current.subject().equals(user.subject())) {
            sessions.refresh(request, response, user);
            log.debug("gate-auth: re-check ok for sub={}", user.subject());
        } else {
            sessions.login(request, response, user);
            log.info("gate-auth: direct login sub={} username={}", user.subject(), user.username());
        }
        response.setStatus(303);
        response.setHeader("Location", Http.contextUrl(request, c.returnPath()));
    }

    private void handleError(HttpServletRequest request, HttpServletResponse response, HandoffCookie c, String error,
                             String loginLink) throws IOException {
        if (c.recheck() && "login_required".equals(error)) {
            // No gate session right now: keep working on the LAN session (spec §6.6).
            sessions.markChecked(request);
            response.setStatus(303);
            response.setHeader("Location", Http.contextUrl(request, c.returnPath()));
            return;
        }
        if ("access_denied".equals(error)) {
            if (c.recheck()) {
                GateUser current = currentDirectUser();
                log.info("gate-auth: access revoked at the gate, ending session sub={}",
                        current == null ? "?" : current.subject());
            }
            sessions.logout(request);
            Http.page(response, 403, "No access", "<p>Your account has no access to this app, or it was blocked.</p>");
            return;
        }
        log.warn("gate-auth: gate answered error={}", error);
        Http.page(response, 400, "Login failed", "<p>The gate refused the login (" + Http.esc(error) + ").</p>"
                + loginLink);
    }

    private static GateUser currentDirectUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        if (a instanceof GateAuthentication ga && ga.getPrincipal().mode() == AuthMode.DIRECT) {
            return ga.getPrincipal();
        }
        return null;
    }

    private static String random() {
        byte[] b = new byte[32];
        RANDOM.nextBytes(b);
        return Base64Url.encode(b);
    }
}
