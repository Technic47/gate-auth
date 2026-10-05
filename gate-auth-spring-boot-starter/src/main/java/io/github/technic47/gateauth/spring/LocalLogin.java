package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateUser;
import io.github.technic47.gateauth.spring.GateAuthProperties.LocalUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.csrf.CsrfToken;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Local (break-glass) login, spec §7: accounts from config, allowed networks only, lockout.
 */
final class LocalLogin {

    private static final Logger log = LoggerFactory.getLogger(LocalLogin.class);

    private final GateAuthSettings settings;
    private final GateSessions sessions;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private final Map<String, Failures> failures = new ConcurrentHashMap<>();
    /** Compared against when the user doesn't exist, so response time doesn't reveal valid names. */
    private final String dummyHash;

    LocalLogin(GateAuthSettings settings, GateSessions sessions) {
        this.settings = settings;
        this.sessions = sessions;
        this.dummyHash = settings.localEnabled() ? encoder.encode(GateClaims.randomId()) : null;
    }

    boolean allowedFrom(HttpServletRequest request) {
        return settings.localEnabled() && settings.isLocalNetwork(request.getRemoteAddr());
    }

    void form(HttpServletRequest request, HttpServletResponse response, String returnPath, String error, int status)
            throws IOException {
        if (!allowedFrom(request)) {
            Http.page(response, 403, "Local login unavailable",
                    "<p>Local login is not available from this network.</p>");
            return;
        }
        CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        String action = Http.contextUrl(request, settings.basePath() + "/local");
        String body = (error == null ? "" : "<p class=\"err\">" + Http.esc(error) + "</p>")
                + "<form method=\"post\" action=\"" + Http.esc(action) + "\">"
                + "<label>Name<input name=\"username\" autocomplete=\"username\" required autofocus></label>"
                + "<label>Password<input name=\"password\" type=\"password\" autocomplete=\"current-password\" required></label>"
                + "<input type=\"hidden\" name=\"redirect\" value=\"" + Http.esc(GateAuthSettings.safeReturnPath(returnPath)) + "\">"
                + (csrf == null ? "" : "<input type=\"hidden\" name=\"" + Http.esc(csrf.getParameterName())
                + "\" value=\"" + Http.esc(csrf.getToken()) + "\">")
                + "<button type=\"submit\">Log in</button></form>"
                + "<p class=\"muted\">Emergency login for when the gate is unreachable.</p>";
        Http.page(response, status, "Local login", body);
    }

    void submit(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String ret = request.getParameter("redirect");
        if (!allowedFrom(request)) {
            log.warn("gate-auth: local login attempt from disallowed address {}", request.getRemoteAddr());
            form(request, response, ret, null, 403);
            return;
        }
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        String ip = request.getRemoteAddr();
        if (username == null || password == null || username.length() > 128 || password.length() > 256) {
            form(request, response, ret, "Wrong name or password.", 401);
            return;
        }
        if (locked("u:" + username) || locked("ip:" + ip)) {
            log.warn("gate-auth: local login locked user={} ip={}", username, ip);
            form(request, response, ret, "Too many attempts. Try again later.", 429);
            return;
        }

        LocalUser account = findUser(username);
        String hash = account == null ? dummyHash : GateAuthSettings.stripBcryptPrefix(account.hash());
        boolean ok = encoder.matches(password, hash) && account != null;
        if (!ok) {
            fail("u:" + username);
            fail("ip:" + ip);
            log.warn("gate-auth: local login failed user={} ip={}", username, ip);
            form(request, response, ret, "Wrong name or password.", 401);
            return;
        }
        failures.remove("u:" + username);
        failures.remove("ip:" + ip);

        String sub = account.linkTo() == null || account.linkTo().isBlank() ? "local:" + account.name() : account.linkTo();
        GateUser user = new GateUser(sub, account.name(), "LOCAL",
                account.roles() == null ? List.of() : account.roles(), List.of(settings.appName()), AuthMode.LOCAL);
        sessions.login(request, response, user);
        log.warn("gate-auth: LOCAL login user={} sub={} ip={}", account.name(), sub, ip);
        response.setStatus(303);
        response.setHeader("Location", Http.contextUrl(request, GateAuthSettings.safeReturnPath(ret)));
    }

    private LocalUser findUser(String name) {
        List<LocalUser> users = settings.props().local().users();
        if (users == null) {
            return null;
        }
        for (LocalUser u : users) {
            if (u.name().equals(name)) {
                return u;
            }
        }
        return null;
    }

    private boolean locked(String key) {
        Failures f = failures.get(key);
        return f != null && f.lockedUntil > sessions.now();
    }

    private void fail(String key) {
        long now = sessions.now();
        if (failures.size() > 10_000) {
            failures.values().removeIf(f -> f.lockedUntil < now && f.lastAt < now - 3600);
        }
        failures.compute(key, (k, f) -> {
            int count = (f == null || f.lastAt < now - settings.props().local().lockout().toSeconds()) ? 1 : f.count + 1;
            long lockedUntil = count >= settings.props().local().maxFailures()
                    ? now + settings.props().local().lockout().toSeconds() : 0;
            return new Failures(count, now, lockedUntil);
        });
    }

    private record Failures(int count, long lastAt, long lockedUntil) {
    }
}
