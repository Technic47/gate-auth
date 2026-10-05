package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.GateUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The library's own endpoints under {@code base-path} (default {@code /auth}). Runs after the CSRF filter, so
 * POSTs here are CSRF-checked (except the callback), and before authorization, so they need no login.
 *
 * <pre>
 * GET  /auth/login?redirect=   entry: picks direct / local / chooser (spec §8)
 * GET  /auth/direct?redirect=  start a direct (gate) login
 * POST /auth/callback          direct-mode handoff answer from the gate
 * GET  /auth/local             local login form;  POST: submit
 * POST /auth/logout            end the app session
 * GET  /auth/me                current user as JSON (401 if none)
 * </pre>
 */
final class GateAuthEndpointsFilter extends OncePerRequestFilter {

    private final GateAuthSettings settings;
    private final GateSessions sessions;
    private final DirectLogin directLogin;
    private final LocalLogin localLogin;

    GateAuthEndpointsFilter(GateAuthSettings settings, GateSessions sessions, DirectLogin directLogin,
                            LocalLogin localLogin) {
        this.settings = settings;
        this.sessions = sessions;
        this.directLogin = directLogin;
        this.localLogin = localLogin;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!settings.isAuthEndpoint(request)) {
            chain.doFilter(request, response);
            return;
        }
        String sub = GateAuthSettings.path(request).substring(settings.basePath().length());
        String method = request.getMethod();
        String ret = request.getParameter("redirect");

        switch (sub) {
            case "/login" -> {
                if (!"GET".equals(method)) {
                    notAllowed(response);
                } else {
                    login(request, response, ret);
                }
            }
            case "/direct" -> {
                if (!settings.directEnabled()) {
                    notFound(response);
                } else if (!"GET".equals(method)) {
                    notAllowed(response);
                } else {
                    directLogin.start(request, response, ret, false);
                }
            }
            case "/callback" -> {
                if (!settings.directEnabled()) {
                    notFound(response);
                } else if (!"POST".equals(method)) {
                    notAllowed(response);
                } else {
                    directLogin.callback(request, response);
                }
            }
            case "/local" -> {
                if (!settings.localEnabled()) {
                    notFound(response);
                } else if ("GET".equals(method)) {
                    localLogin.form(request, response, ret, null, 200);
                } else if ("POST".equals(method)) {
                    localLogin.submit(request, response);
                } else {
                    notAllowed(response);
                }
            }
            case "/logout" -> {
                if (!"POST".equals(method)) {
                    notAllowed(response);
                } else {
                    logout(request, response);
                }
            }
            case "/me" -> {
                if (!"GET".equals(method)) {
                    notAllowed(response);
                } else {
                    me(request, response);
                }
            }
            default -> notFound(response);
        }
    }

    private void login(HttpServletRequest request, HttpServletResponse response, String ret) throws IOException {
        String target = GateAuthSettings.safeReturnPath(ret);
        if (currentUser() != null) {
            response.sendRedirect(Http.contextUrl(request, target));
            return;
        }
        boolean direct = settings.directEnabled();
        boolean local = localLogin.allowedFrom(request);
        if (direct && !local) {
            directLogin.start(request, response, target, false);
        } else if (local && !direct) {
            localLogin.form(request, response, target, null, 200);
        } else if (direct) {
            String q = "?redirect=" + Http.url(target);
            Http.page(response, 200, "Log in",
                    "<a class=\"btn\" href=\"" + Http.esc(Http.contextUrl(request, settings.basePath() + "/direct" + q))
                            + "\">Log in via Gate</a>"
                            + "<a class=\"btn alt\" href=\"" + Http.esc(Http.contextUrl(request, settings.basePath() + "/local" + q))
                            + "\">Local login</a>"
                            + "<p class=\"muted\">Use local login only when the gate is unreachable.</p>");
        } else {
            StringBuilder links = new StringBuilder();
            for (String url : settings.props().publicUrls()) {
                links.append("<li>").append(Http.esc(url)).append("</li>");
            }
            Http.page(response, 401, "Not signed in",
                    "<p>This app is opened through the gate. Use one of:</p><ul>" + links + "</ul>");
        }
    }

    private void logout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        sessions.logout(request);
        Map<String, Object> body = new LinkedHashMap<>();
        if (settings.gateUrl() != null) {
            body.put("gate_logout_url", settings.gateUrl() + "/logout");
        }
        if (Http.wantsHtml(request)) {
            response.setStatus(303);
            response.setHeader("Location", Http.contextUrl(request, "/"));
            return;
        }
        Http.json(response, 200, body, "application/json");
    }

    private void me(HttpServletRequest request, HttpServletResponse response) throws IOException {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        GateUser user = currentUser();
        if (user == null) {
            Http.problem(response, 401, "Unauthorized", Http.contextUrl(request, settings.basePath() + "/login"));
            return;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", user.subject());
        body.put("username", user.username());
        body.put("gate_role", user.gateRole());
        body.put("roles", user.roles());
        body.put("authorities", a.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        body.put("svc", user.services());
        body.put("mode", user.mode().name());
        if (settings.gateUrl() != null) {
            body.put("gate_logout_url", settings.gateUrl() + "/logout");
        }
        Http.json(response, 200, body, "application/json");
    }

    private static GateUser currentUser() {
        Authentication a = SecurityContextHolder.getContext().getAuthentication();
        return a instanceof GateAuthentication ga ? ga.getPrincipal() : null;
    }

    private static void notFound(HttpServletResponse response) throws IOException {
        Http.problem(response, 404, "Not Found", null);
    }

    private static void notAllowed(HttpServletResponse response) throws IOException {
        response.setHeader("Allow", String.join(", ", List.of("GET", "POST")));
        Http.problem(response, 405, "Method Not Allowed", null);
    }
}
