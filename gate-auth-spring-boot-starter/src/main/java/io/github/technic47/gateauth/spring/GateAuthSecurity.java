package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.ReplayGuard;
import io.github.technic47.gateauth.core.TokenVerifier;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.time.Clock;

/**
 * Applies Gate Auth to an {@link HttpSecurity}. The starter does this for you unless the app defines its own
 * {@code SecurityFilterChain}; then call it yourself:
 *
 * <pre>{@code
 * @Bean
 * SecurityFilterChain security(HttpSecurity http, GateAuthSecurity gateAuth) throws Exception {
 *     gateAuth.configure(http);
 *     http.authorizeHttpRequests(a -> a
 *             .requestMatchers("/api/admin/**").hasRole("ADMIN")
 *             .anyRequest().authenticated());
 *     return http.build();
 * }
 * }</pre>
 */
public final class GateAuthSecurity {

    private final GateAuthSettings settings;
    private final GateSessions sessions;
    private final TokenVerifier verifier;
    private final DirectLogin directLogin;
    private final LocalLogin localLogin;
    private final GateReachability reachability;
    private final java.util.function.Consumer<Long> roleVersionSeen;

    /**
     * Creates the configurer. Normally a bean from {@link GateAuthAutoConfiguration}; inject it instead of
     * constructing it.
     *
     * @param settings     validated settings
     * @param replayGuard  single-use check for handoff tokens
     * @param reachability whether the gate can be reached (for silent re-checks)
     * @param clock        source of the current time
     */
    public GateAuthSecurity(GateAuthSettings settings, ReplayGuard replayGuard, GateReachability reachability,
                            Clock clock) {
        this(settings, replayGuard, reachability, clock, null);
    }

    /**
     * Creates the configurer with role catalog sync: every verified token's {@code rv} is passed on, so a newer
     * catalog is fetched at once (spec §4.5).
     *
     * @param settings     validated settings
     * @param replayGuard  single-use check for handoff tokens
     * @param reachability whether the gate can be reached (for silent re-checks)
     * @param clock        source of the current time
     * @param roles        the synced role catalog, or {@code null} when {@code gate.auth.roles.enabled} is off
     */
    public GateAuthSecurity(GateAuthSettings settings, ReplayGuard replayGuard, GateReachability reachability,
                            Clock clock, GateRoleCatalog roles) {
        this.settings = settings;
        this.roleVersionSeen = roles == null ? v -> { } : roles::versionSeen;
        this.sessions = new GateSessions(settings, clock);
        this.verifier = settings.keys() == null ? null
                : new TokenVerifier(settings.keys(), settings.props().issuer(), settings.appName(),
                settings.props().clockSkew(), clock);
        this.directLogin = settings.directEnabled()
                ? new DirectLogin(settings, verifier, replayGuard, sessions, roleVersionSeen) : null;
        this.localLogin = new LocalLogin(settings, sessions);
        this.reachability = reachability;
    }

    /**
     * The settings this configurer uses.
     *
     * @return validated settings
     */
    public GateAuthSettings settings() {
        return settings;
    }

    /**
     * Adds Gate Auth to a filter chain: the mode filters, {@code /auth/*} endpoints, CSRF (cookie + header for
     * SPAs), Origin checks, entry point and access-denied handling. Form login, HTTP Basic and Spring's default
     * logout are switched off. Call it before your own {@code authorizeHttpRequests} rules.
     *
     * @param http the filter chain being built
     * @throws Exception if Spring Security rejects the configuration
     */
    public void configure(HttpSecurity http) throws Exception {
        CookieCsrfTokenRepository csrfRepository = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepository.setCookieName(settings.csrfCookieName());
        csrfRepository.setHeaderName("X-XSRF-TOKEN");
        csrfRepository.setCookieCustomizer(c -> c.path("/").secure(settings.cookieSecure()).sameSite("Strict"));

        RequestMatcher callback = request -> settings.directEnabled() && "POST".equals(request.getMethod())
                && GateAuthSettings.path(request).equals(settings.callbackPath());

        GateAuthEntryPoint entryPoint = new GateAuthEntryPoint(settings);

        http.csrf(c -> c
                        .csrfTokenRepository(csrfRepository)
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
                        .ignoringRequestMatchers(callback))
                // We carry the return path ourselves (?redirect=); no server-side saved requests.
                .requestCache(c -> c.requestCache(new NullRequestCache()))
                .exceptionHandling(e -> e.authenticationEntryPoint(entryPoint).accessDeniedHandler(entryPoint))
                .formLogin(f -> f.disable())
                .httpBasic(b -> b.disable())
                .logout(l -> l.disable());

        http.addFilterAfter(new GateAuthFilter(settings, verifier, sessions, roleVersionSeen),
                SecurityContextHolderFilter.class);
        http.addFilterBefore(new OriginCheckFilter(settings), CsrfFilter.class);
        http.addFilterAfter(new GateAuthEndpointsFilter(settings, sessions, directLogin, localLogin), CsrfFilter.class);
        if (settings.directEnabled()) {
            http.addFilterBefore(new DirectRecheckFilter(settings, sessions, directLogin, reachability),
                    AuthorizationFilter.class);
        }
    }
}
