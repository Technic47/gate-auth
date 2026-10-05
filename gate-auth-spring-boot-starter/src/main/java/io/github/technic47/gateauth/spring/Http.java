package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.Json;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/** Small response helpers shared by the filters: Problem Details, HTML pages, cookies. */
final class Http {

    private Http() {
    }

    static void problem(HttpServletResponse response, int status, String title, String loginUrl) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("type", "about:blank");
        body.put("title", title);
        body.put("status", status);
        if (loginUrl != null) {
            body.put("login_url", loginUrl);
        }
        json(response, status, body, "application/problem+json");
    }

    static void json(HttpServletResponse response, int status, Map<String, Object> body, String contentType)
            throws IOException {
        response.setStatus(status);
        response.setContentType(contentType);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(Json.write(body));
    }

    /** Minimal self-contained page. {@code bodyHtml} must already be escaped. */
    static void page(HttpServletResponse response, int status, String title, String bodyHtml) throws IOException {
        response.setStatus(status);
        response.setContentType("text/html");
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.getWriter().write("""
                <!doctype html><html><head><meta charset="utf-8">
                <meta name="viewport" content="width=device-width,initial-scale=1">
                <title>%s</title>
                <style>
                body{font:15px/1.5 system-ui,sans-serif;background:#f5f5f4;color:#1c1917;margin:0;padding:24px 16px}
                main{max-width:380px;margin:8vh auto;background:#fff;border:1px solid #e7e5e4;border-radius:10px;padding:24px}
                h1{font-size:19px;margin:0 0 16px}
                a.btn,button{display:block;width:100%%;box-sizing:border-box;text-align:center;padding:10px;margin:10px 0;
                  border-radius:7px;border:1px solid #1c1917;background:#1c1917;color:#fff;font:inherit;text-decoration:none;cursor:pointer}
                a.btn.alt{background:#fff;color:#1c1917}
                input{display:block;width:100%%;box-sizing:border-box;padding:9px;margin:4px 0 12px;border:1px solid #a8a29e;border-radius:7px;font:inherit}
                .err{color:#b91c1c}.muted{color:#78716c;font-size:13px}
                </style></head><body><main><h1>%s</h1>%s</main></body></html>
                """.formatted(esc(title), esc(title), bodyHtml));
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '&' -> sb.append("&amp;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    static String url(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static boolean wantsHtml(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        return accept != null && accept.contains("text/html");
    }

    /** Top-level page navigation (not fetch/XHR, not images/scripts). */
    static boolean isNavigation(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod())) {
            return false;
        }
        String mode = request.getHeader("Sec-Fetch-Mode");
        if (mode != null) {
            return "navigate".equals(mode);
        }
        return wantsHtml(request);
    }

    static String cookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }

    /** Writes a Set-Cookie header with explicit attributes (servlet Cookie API can't set SameSite portably). */
    static void setCookie(HttpServletResponse response, String name, String value, String path, long maxAgeSeconds,
                          String sameSite, boolean secure) {
        StringBuilder sb = new StringBuilder();
        sb.append(name).append('=').append(value == null ? "" : value);
        sb.append("; Path=").append(path);
        sb.append("; Max-Age=").append(maxAgeSeconds);
        sb.append("; HttpOnly");
        if (secure) {
            sb.append("; Secure");
        }
        sb.append("; SameSite=").append(sameSite);
        response.addHeader("Set-Cookie", sb.toString());
    }

    static String contextUrl(HttpServletRequest request, String path) {
        return request.getContextPath() + path;
    }
}
