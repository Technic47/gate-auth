package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.Ed25519Keys;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.TokenSigner;
import io.github.technic47.gateauth.core.TokenType;
import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class GateAuthIntegrationTest {

    private static final GateSigningKey GATE_KEY = GateSigningKey.generate();
    private static final TokenSigner GATE = new TokenSigner(GATE_KEY);
    private static final String LOCAL_PASSWORD = "correct horse battery staple";
    private static final String LAN_IP = "192.168.1.10";
    private static final String OTHER_IP = "10.9.9.9";
    private static final String ORIGIN = "http://localhost";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("gate.auth.app-name", () -> "bikeservice");
        r.add("gate.auth.public-urls", () -> "http://localhost,https://192.168.1.50:8443");
        r.add("gate.auth.public-keys", () -> Ed25519Keys.toPem(GATE_KEY.publicKey()));
        r.add("gate.auth.admin-implies-roles", () -> "admin");
        r.add("gate.auth.local-secret", () -> "0123456789abcdef0123456789abcdef-test");
        r.add("gate.auth.edge.enabled", () -> "true");
        r.add("gate.auth.direct.enabled", () -> "true");
        r.add("gate.auth.direct.gate-url", () -> "https://144.31.187.7");
        r.add("gate.auth.local.enabled", () -> "true");
        r.add("gate.auth.local.allowed-networks", () -> "192.168.1.0/24");
        r.add("gate.auth.local.users[0].name", () -> "admin");
        r.add("gate.auth.local.users[0].hash", () -> new BCryptPasswordEncoder(4).encode(LOCAL_PASSWORD));
        r.add("gate.auth.local.users[0].roles", () -> "admin");
        r.add("gate.auth.local.users[0].link-to", () -> "1");
    }

    @Autowired
    WebApplicationContext context;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        // The real filter chain, without spring-security-test's MockMvc configurer (it swaps CSRF/session behaviour).
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .addFilters(context.getBean("springSecurityFilterChain", Filter.class)).build();
    }

    // ------------------------------------------------------------------ edge

    @Test
    void edgeAssertionAuthenticatesWithoutSession() throws Exception {
        var request = mvc.perform(get("/api/hello").header("X-Gate-Assertion", assertion("42", "bikeservice", "USER", List.of("member"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("42"))
                .andExpect(jsonPath("$.mode").value("EDGE"))
                .andExpect(jsonPath("$.roles[0]").value("member"))
                .andReturn().getRequest();
        assertThat(request.getSession(false)).isNull();
    }

    @Test
    void edgeAssertionForAnotherAppIsRejected() throws Exception {
        mvc.perform(get("/api/hello").header("X-Gate-Assertion", assertion("42", "fashionmark", "USER", List.of())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void invalidAssertionNeverFallsBackToSession() throws Exception {
        MockHttpSession session = directLogin("7");
        String forged = new TokenSigner(GateSigningKey.generate()).sign(TokenType.ASSERTION,
                GateClaims.builder().subject("42").audience("bikeservice").build(TokenType.ASSERTION));
        mvc.perform(get("/api/hello").session(session).header("X-Gate-Assertion", forged))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void gateAdminGetsImpliedRoles() throws Exception {
        mvc.perform(get("/auth/me").header("X-Gate-Assertion", assertion("1", "bikeservice", "ADMIN", List.of())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.authorities[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.mode").value("EDGE"));
    }

    // ------------------------------------------------------------------ unauthenticated

    @Test
    void apiWithoutAuthGetsProblemWithLoginUrl() throws Exception {
        mvc.perform(get("/api/hello"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.login_url").value("/auth/login"));
    }

    @Test
    void pageNavigationIsRedirectedToLogin() throws Exception {
        MockHttpServletResponse res = mvc.perform(get("/page").header("Sec-Fetch-Mode", "navigate"))
                .andExpect(status().isFound()).andReturn().getResponse();
        assertThat(res.getRedirectedUrl()).isEqualTo("/auth/login?redirect=%2Fpage");
    }

    // ------------------------------------------------------------------ direct

    @Test
    void loginFromOutsideLocalNetworksGoesStraightToGate() throws Exception {
        MockHttpServletResponse res = mvc.perform(get("/auth/login").param("redirect", "/page").with(from(OTHER_IP)))
                .andExpect(status().isFound()).andReturn().getResponse();
        UriComponents gate = UriComponentsBuilder.fromUriString(res.getRedirectedUrl()).build();
        assertThat(gate.getHost()).isEqualTo("144.31.187.7");
        assertThat(gate.getPath()).isEqualTo("/auth/handoff");
        assertThat(gate.getQueryParams().getFirst("client_id")).isEqualTo("bikeservice");
        assertThat(gate.getQueryParams().getFirst("response_mode")).isEqualTo("form_post");
        assertThat(decode(gate.getQueryParams().getFirst("redirect_uri"))).isEqualTo("http://localhost/auth/callback");
        assertThat(gate.getQueryParams().getFirst("prompt")).isNull();
        assertThat(res.getHeaders("Set-Cookie")).filteredOn(h -> h.startsWith("BIKESERVICE_HANDOFF=")).singleElement()
                .asString().contains("SameSite=None")
                .contains("HttpOnly").contains("Path=/auth/callback");
    }

    @Test
    void unknownHostCannotStartDirectLogin() throws Exception {
        mvc.perform(get("/auth/direct").with(r -> { r.setServerName("evil.example"); return r; }))
                .andExpect(status().isBadRequest());
    }

    @Test
    void fullDirectLoginCreatesSession() throws Exception {
        MockHttpSession session = directLogin("42");
        mvc.perform(get("/api/hello").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sub").value("42"))
                .andExpect(jsonPath("$.mode").value("DIRECT"));
    }

    @Test
    void handoffTokenCannotBeReplayed() throws Exception {
        Handoff h = startDirect(false);
        String token = handoff("42", h.nonce);
        mvc.perform(callback(h, token)).andExpect(status().isSeeOther());
        mvc.perform(callback(h, token)).andExpect(status().isUnauthorized());
    }

    @Test
    void wrongStateIsRejected() throws Exception {
        Handoff h = startDirect(false);
        mvc.perform(post("/auth/callback").cookie(h.cookie).param("state", "other").param("id_token", handoff("42", h.nonce)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void handoffWithWrongNonceIsRejected() throws Exception {
        Handoff h = startDirect(false);
        mvc.perform(callback(h, handoff("42", "not-the-nonce"))).andExpect(status().isUnauthorized());
    }

    @Test
    void callbackWithoutCookieIsRejected() throws Exception {
        Handoff h = startDirect(false);
        mvc.perform(post("/auth/callback").param("state", h.state).param("id_token", handoff("42", h.nonce)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void accessDeniedFromGateShowsNoAccess() throws Exception {
        Handoff h = startDirect(false);
        mvc.perform(post("/auth/callback").cookie(h.cookie).param("state", h.state).param("error", "access_denied"))
                .andExpect(status().isForbidden());
    }

    @Test
    void staleDirectSessionIsSilentlyRechecked() throws Exception {
        MockHttpSession session = directLogin("42");
        session.setAttribute(GateSessions.LAST_CHECKED, 0L);

        MockHttpServletResponse res = mvc.perform(get("/page").session(session).header("Sec-Fetch-Mode", "navigate"))
                .andExpect(status().isFound()).andReturn().getResponse();
        UriComponents gate = UriComponentsBuilder.fromUriString(res.getRedirectedUrl()).build();
        assertThat(gate.getQueryParams().getFirst("prompt")).isEqualTo("none");

        // API calls never trigger the re-check
        mvc.perform(get("/api/hello").session(session)).andExpect(status().isOk());

        // gate says "no gate session": LAN session stays
        Handoff h = handoffFrom(res);
        mvc.perform(post("/auth/callback").session(session).cookie(h.cookie).param("state", h.state)
                        .param("error", "login_required"))
                .andExpect(status().isSeeOther());
        mvc.perform(get("/api/hello").session(session)).andExpect(status().isOk());
        assertThat((Long) session.getAttribute(GateSessions.LAST_CHECKED)).isGreaterThan(0L);
    }

    @Test
    void recheckWithAccessDeniedEndsSession() throws Exception {
        MockHttpSession session = directLogin("42");
        session.setAttribute(GateSessions.LAST_CHECKED, 0L);
        MockHttpServletResponse res = mvc.perform(get("/page").session(session).header("Sec-Fetch-Mode", "navigate"))
                .andReturn().getResponse();
        Handoff h = handoffFrom(res);
        mvc.perform(post("/auth/callback").session(session).cookie(h.cookie).param("state", h.state)
                        .param("error", "access_denied"))
                .andExpect(status().isForbidden());
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void sessionEndsAfterAbsoluteLifetime() throws Exception {
        MockHttpSession session = directLogin("42");
        session.setAttribute(GateSessions.LOGIN_AT, 0L);
        mvc.perform(get("/api/hello").session(session)).andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ local

    @Test
    void lanUserSeesChooser() throws Exception {
        String html = mvc.perform(get("/auth/login").with(from(LAN_IP)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(html).contains("Log in via Gate").contains("Local login");
    }

    @Test
    void localLoginWorksFromLanAndActsAsLinkedUser() throws Exception {
        MockHttpServletResponse res = mvc.perform(post("/auth/local").with(from(LAN_IP)).with(xsrf())
                        .header("Origin", ORIGIN)
                        .param("username", "admin").param("password", LOCAL_PASSWORD).param("redirect", "/page"))
                .andExpect(status().isSeeOther()).andReturn().getResponse();
        assertThat(res.getHeader("Location")).isEqualTo("/page");
        MockHttpSession session = (MockHttpSession) mvc.perform(post("/auth/local").with(from(LAN_IP)).with(xsrf())
                .header("Origin", ORIGIN).param("username", "admin").param("password", LOCAL_PASSWORD))
                .andReturn().getRequest().getSession(false);
        mvc.perform(get("/api/hello").session(session))
                .andExpect(jsonPath("$.sub").value("1"))
                .andExpect(jsonPath("$.mode").value("LOCAL"));
    }

    @Test
    void localLoginFormPostWithMaskedFormTokenWorks() throws Exception {
        MockHttpServletResponse form = mvc.perform(get("/auth/local").with(from(LAN_IP)))
                .andExpect(status().isOk()).andReturn().getResponse();
        Cookie cookie = form.getCookie("BIKESERVICE_XSRF");
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("name=\"_csrf\" value=\"([^\"]+)\"")
                .matcher(form.getContentAsString());
        assertThat(m.find()).isTrue();
        assertThat(m.group(1)).isNotEqualTo(cookie.getValue()); // BREACH-masked in the page
        mvc.perform(post("/auth/local").with(from(LAN_IP)).cookie(cookie).header("Origin", ORIGIN)
                        .param("_csrf", m.group(1)).param("username", "admin").param("password", LOCAL_PASSWORD))
                .andExpect(status().isSeeOther());
    }

    @Test
    void localLoginRejectedFromOtherNetworks() throws Exception {
        mvc.perform(post("/auth/local").with(from(OTHER_IP)).with(xsrf()).header("Origin", ORIGIN)
                        .param("username", "admin").param("password", LOCAL_PASSWORD))
                .andExpect(status().isForbidden());
        mvc.perform(get("/auth/local").with(from(OTHER_IP))).andExpect(status().isForbidden());
    }

    @Test
    void wrongLocalPasswordIsRejected() throws Exception {
        mvc.perform(post("/auth/local").with(from("192.168.1.77")).with(xsrf()).header("Origin", ORIGIN)
                        .param("username", "admin").param("password", "nope"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void localLoginLocksAfterTooManyFailures() throws Exception {
        for (int i = 0; i < 5; i++) {
            mvc.perform(post("/auth/local").with(from("192.168.1.99")).with(xsrf()).header("Origin", ORIGIN)
                    .param("username", "ghost").param("password", "nope"));
        }
        mvc.perform(post("/auth/local").with(from("192.168.1.99")).with(xsrf()).header("Origin", ORIGIN)
                        .param("username", "ghost").param("password", "nope"))
                .andExpect(status().isTooManyRequests());
    }

    // ------------------------------------------------------------------ CSRF / Origin

    @Test
    void unsafeRequestNeedsOwnOriginAndCsrfToken() throws Exception {
        String a = assertion("42", "bikeservice", "USER", List.of());
        // What a SPA does: read the raw token from the XSRF cookie, send it back as header + cookie.
        MockHttpServletResponse first = mvc.perform(get("/api/hello").header("X-Gate-Assertion", a)).andReturn().getResponse();
        Cookie xsrf = first.getCookie("BIKESERVICE_XSRF");
        assertThat(xsrf).isNotNull();
        assertThat(xsrf.isHttpOnly()).isFalse();

        mvc.perform(post("/api/echo").header("X-Gate-Assertion", a).cookie(xsrf)
                        .header("X-XSRF-TOKEN", xsrf.getValue()).header("Origin", ORIGIN))
                .andExpect(status().isOk());
        // another app on the same IP (other port)
        mvc.perform(post("/api/echo").header("X-Gate-Assertion", a).cookie(xsrf)
                        .header("X-XSRF-TOKEN", xsrf.getValue()).header("Origin", "https://144.31.187.7:8843"))
                .andExpect(status().isForbidden());
        // no Origin / Referer
        mvc.perform(post("/api/echo").header("X-Gate-Assertion", a).cookie(xsrf)
                        .header("X-XSRF-TOKEN", xsrf.getValue()))
                .andExpect(status().isForbidden());
        // no CSRF token
        mvc.perform(post("/api/echo").header("X-Gate-Assertion", a).cookie(xsrf).header("Origin", ORIGIN))
                .andExpect(status().isForbidden());
    }

    @Test
    void logoutEndsSession() throws Exception {
        MockHttpSession session = directLogin("42");
        mvc.perform(post("/auth/logout").session(session).with(xsrf()).header("Origin", ORIGIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.gate_logout_url").value("https://144.31.187.7/logout"));
        assertThat(session.isInvalid()).isTrue();
    }

    // ------------------------------------------------------------------ helpers

    private record Handoff(String state, String nonce, Cookie cookie) {
    }

    private static String assertion(String sub, String aud, String gateRole, List<String> roles) {
        return GATE.sign(TokenType.ASSERTION, GateClaims.builder().subject(sub).preferredUsername("user" + sub)
                .audience(aud).gateRole(gateRole).roles(roles).build(TokenType.ASSERTION));
    }

    private static String handoff(String sub, String nonce) {
        return GATE.sign(TokenType.HANDOFF, GateClaims.builder().subject(sub).preferredUsername("user" + sub)
                .audience("bikeservice").gateRole("USER").nonce(nonce).build(TokenType.HANDOFF));
    }

    private Handoff startDirect(boolean silent) throws Exception {
        MockHttpServletResponse res = mvc.perform(get("/auth/direct").param("redirect", "/page"))
                .andExpect(status().isFound()).andReturn().getResponse();
        return handoffFrom(res);
    }

    private static Handoff handoffFrom(MockHttpServletResponse res) {
        UriComponents gate = UriComponentsBuilder.fromUriString(res.getRedirectedUrl()).build();
        String setCookie = res.getHeaders("Set-Cookie").stream().filter(h -> h.startsWith("BIKESERVICE_HANDOFF="))
                .findFirst().orElseThrow();
        String value = setCookie.substring("BIKESERVICE_HANDOFF=".length(), setCookie.indexOf(';'));
        return new Handoff(gate.getQueryParams().getFirst("state"), gate.getQueryParams().getFirst("nonce"),
                new Cookie("BIKESERVICE_HANDOFF", value));
    }

    private MockHttpServletRequestBuilder callback(Handoff h, String token) {
        return post("/auth/callback").cookie(h.cookie).param("state", h.state).param("id_token", token);
    }

    private MockHttpSession directLogin(String sub) throws Exception {
        Handoff h = startDirect(false);
        return (MockHttpSession) mvc.perform(callback(h, handoff(sub, h.nonce)))
                .andExpect(status().isSeeOther())
                .andReturn().getRequest().getSession(false);
    }

    /**
     * Real browser behaviour instead of spring-security-test's csrf() (which swaps the repository inside the shared
     * filter): fetch the XSRF cookie, send it back as cookie + X-XSRF-TOKEN header.
     */
    private RequestPostProcessor xsrf() throws Exception {
        Cookie cookie = mvc.perform(get("/auth/me")).andReturn().getResponse().getCookie("BIKESERVICE_XSRF");
        assertThat(cookie).isNotNull();
        return r -> {
            Cookie[] existing = r.getCookies() == null ? new Cookie[0] : r.getCookies();
            Cookie[] all = java.util.Arrays.copyOf(existing, existing.length + 1);
            all[existing.length] = cookie;
            r.setCookies(all);
            r.addHeader("X-XSRF-TOKEN", cookie.getValue());
            return r;
        };
    }

    private static RequestPostProcessor from(String ip) {
        return r -> {
            r.setRemoteAddr(ip);
            return r;
        };
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }
}
