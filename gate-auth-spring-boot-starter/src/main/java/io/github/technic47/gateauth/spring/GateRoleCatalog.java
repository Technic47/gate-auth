package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.RoleCatalog;
import io.github.technic47.gateauth.core.TokenValidationException;
import io.github.technic47.gateauth.core.TokenVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.SmartLifecycle;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The roles this app may receive, synced from the gate (spec §4.5). The gate defines roles; the app fetches its
 * signed catalog at start, every {@code gate.auth.roles.refresh}, and at once when a verified token carries a newer
 * {@code rv} (at most once a minute). An older catalog never replaces a newer one, and while the gate is unreachable
 * the last verified catalog stays. Changes are published as {@link GateRolesChangedEvent}.
 *
 * <p>Authorization never depends on this list: it uses the token's {@code roles}. A role the app doesn't handle
 * must grant nothing; this class only reports such roles (and handled roles the gate doesn't offer) in the log.
 */
public final class GateRoleCatalog implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(GateRoleCatalog.class);
    /** Earliest re-fetch after the previous one when a token announces a newer catalog. */
    static final Duration MIN_TRIGGERED_INTERVAL = Duration.ofMinutes(1);

    private final URI url;
    private final TokenVerifier verifier;
    private final Duration refresh;
    private final Set<String> handled;
    private final ApplicationEventPublisher events;
    private final Clock clock;
    private final HttpClient http;
    private final AtomicReference<RoleCatalog> current = new AtomicReference<>();
    private volatile Instant lastFetch = Instant.EPOCH;
    private volatile boolean failing;
    private ScheduledExecutorService scheduler;

    /**
     * Creates the catalog; it starts fetching when the application context starts.
     *
     * @param settings validated settings with {@code gate.auth.roles.enabled}
     * @param events   where {@link GateRolesChangedEvent} goes
     * @param clock    source of the current time
     */
    public GateRoleCatalog(GateAuthSettings settings, ApplicationEventPublisher events, Clock clock) {
        if (!settings.rolesEnabled()) {
            throw new IllegalStateException("gate.auth.roles.enabled is false");
        }
        this.url = URI.create(settings.rolesGateUrl() + "/.well-known/gate/apps/"
                + URLEncoder.encode(settings.appName(), StandardCharsets.UTF_8) + "/roles");
        this.verifier = new TokenVerifier(settings.keys(), settings.props().issuer(), settings.appName(),
                settings.props().clockSkew(), clock);
        this.refresh = settings.props().roles().refresh();
        List<String> h = settings.props().roles().handled();
        this.handled = h == null ? Set.of() : Set.copyOf(h);
        this.events = events;
        this.clock = clock;
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER);
        if (settings.props().roles().trustAnyTlsCertificate()) {
            builder.sslContext(trustAnySslContext());
        }
        this.http = builder.build();
    }

    /**
     * The latest verified catalog.
     *
     * @return the catalog, empty until the first successful fetch
     */
    public Optional<RoleCatalog> current() {
        return Optional.ofNullable(current.get());
    }

    /**
     * The display name of a role, for UIs.
     *
     * @param code role code from a token
     * @return the gate's name, or the code itself while the catalog doesn't know it
     */
    public String displayName(String code) {
        RoleCatalog c = current.get();
        RoleCatalog.Role role = c == null ? null : c.find(code);
        return role == null ? code : role.name();
    }

    /**
     * Called with the {@code rv} of every verified token: a newer version than the current catalog triggers a fetch
     * in the background (at most once per {@link #MIN_TRIGGERED_INTERVAL}).
     *
     * @param roleVersion the token's {@code rv}, or {@code null} (gates before 0.3.0)
     */
    public void versionSeen(Long roleVersion) {
        if (roleVersion == null) {
            return;
        }
        RoleCatalog c = current.get();
        if (c != null && roleVersion <= c.catalogVersion()) {
            return;
        }
        ScheduledExecutorService s = scheduler;
        if (s != null && Duration.between(lastFetch, clock.instant()).compareTo(MIN_TRIGGERED_INTERVAL) >= 0) {
            lastFetch = clock.instant();
            s.execute(this::refreshQuietly);
        }
    }

    /**
     * Fetches the catalog now. Normally runs on its own schedule; useful in tests and after a manual change.
     *
     * @return {@code true} if a newer catalog was taken over
     * @throws IOException              if the gate can't be reached or answers with an error
     * @throws TokenValidationException if the answer is not a valid catalog for this app
     */
    public synchronized boolean refresh() throws IOException, TokenValidationException {
        lastFetch = clock.instant();
        HttpResponse<String> response;
        try {
            response = http.send(HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/jwt").GET().build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        }
        if (response.statusCode() != 200) {
            throw new IOException("gate answered HTTP " + response.statusCode() + " for " + url);
        }
        RoleCatalog fetched = verifier.verifyRoleCatalog(response.body().strip());
        RoleCatalog previous = current.get();
        if (previous != null && fetched.catalogVersion() <= previous.catalogVersion()) {
            return false;
        }
        current.set(fetched);
        log.info("gate-auth: role catalog rv={} for {}: {}", fetched.catalogVersion(), fetched.audience(),
                fetched.roles().stream().map(RoleCatalog.Role::code).toList());
        reportDifferences(fetched);
        events.publishEvent(new GateRolesChangedEvent(previous, fetched));
        return true;
    }

    private void refreshQuietly() {
        try {
            refresh();
            if (failing) {
                log.info("gate-auth: role catalog reachable again at {}", url);
                failing = false;
            }
        } catch (IOException | TokenValidationException | RuntimeException e) {
            if (!failing) {
                log.warn("gate-auth: role catalog not updated ({}); keeping {}", e.getMessage(),
                        current.get() == null ? "none" : "rv=" + current.get().catalogVersion());
                failing = true;
            } else {
                log.debug("gate-auth: role catalog still not reachable: {}", e.getMessage());
            }
        }
    }

    private void reportDifferences(RoleCatalog catalog) {
        if (handled.isEmpty()) {
            return;
        }
        Set<String> offered = new TreeSet<>(catalog.roles().stream().map(RoleCatalog.Role::code).toList());
        Set<String> unknown = new TreeSet<>(offered);
        unknown.removeAll(handled);
        Set<String> missing = new TreeSet<>(handled);
        missing.removeAll(offered);
        if (!unknown.isEmpty()) {
            log.warn("gate-auth: the gate offers roles this app doesn't handle (they grant nothing until configured): {}",
                    unknown);
        }
        if (!missing.isEmpty()) {
            log.warn("gate-auth: roles this app handles are not offered by the gate (nobody can receive them): {}",
                    missing);
        }
    }

    // ---------------------------------------------------------------- lifecycle

    @Override
    public synchronized void start() {
        if (scheduler != null) {
            return;
        }
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "gate-auth-roles");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleWithFixedDelay(this::refreshQuietly, 0, refresh.toSeconds(), TimeUnit.SECONDS);
    }

    @Override
    public synchronized void stop() {
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
    }

    @Override
    public synchronized boolean isRunning() {
        return scheduler != null;
    }

    // ---------------------------------------------------------------- TLS

    /**
     * The gate runs on a bare IP with a self-signed certificate. The catalog is signed with the gate's key and
     * verified, so the transport doesn't have to prove the gate's identity; this context accepts any certificate
     * for this one client only (nothing global is changed).
     */
    private static SSLContext trustAnySslContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new javax.net.ssl.TrustManager[]{new X509ExtendedTrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) { }
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { }
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, null);
            return ctx;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("TLS context for the role catalog", e);
        }
    }
}
