package io.github.technic47.gateauth.spring;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

/**
 * Spec §8 step 3 and §10: API paths get Problem Details with {@code login_url}; pages are sent to the login entry.
 */
final class GateAuthEntryPoint implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final GateAuthSettings settings;

    GateAuthEntryPoint(GateAuthSettings settings) {
        this.settings = settings;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
            throws IOException {
        String loginUrl = Http.contextUrl(request, settings.basePath() + "/login");
        if (settings.isApi(request) || !Http.isNavigation(request)) {
            Http.problem(response, 401, "Unauthorized", loginUrl);
            return;
        }
        String query = request.getQueryString();
        String ret = GateAuthSettings.path(request) + (query == null ? "" : "?" + query);
        response.setHeader("Cache-Control", "no-store");
        response.sendRedirect(loginUrl + "?redirect=" + Http.url(GateAuthSettings.safeReturnPath(ret)));
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e)
            throws IOException {
        if (settings.isApi(request) || !Http.wantsHtml(request)) {
            Http.problem(response, 403, "Forbidden", null);
        } else {
            Http.page(response, 403, "No access", "<p>You don't have permission for this page.</p>");
        }
    }
}
