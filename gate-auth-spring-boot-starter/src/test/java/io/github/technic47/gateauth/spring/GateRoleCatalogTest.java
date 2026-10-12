package io.github.technic47.gateauth.spring;

import com.sun.net.httpserver.HttpServer;
import io.github.technic47.gateauth.core.Ed25519Keys;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.RoleCatalog;
import io.github.technic47.gateauth.core.TokenSigner;
import io.github.technic47.gateauth.core.TokenValidationException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GateRoleCatalogTest {

    private static final GateSigningKey GATE_KEY = GateSigningKey.generate();
    private static final TokenSigner GATE = new TokenSigner(GATE_KEY);

    private HttpServer gate;
    private final AtomicReference<String> body = new AtomicReference<>();
    private final AtomicInteger status = new AtomicInteger(200);
    private final AtomicInteger requests = new AtomicInteger();
    private final List<GateRolesChangedEvent> events = new CopyOnWriteArrayList<>();
    private GateRoleCatalog catalog;

    @BeforeEach
    void startGate() throws IOException {
        gate = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        gate.createContext("/.well-known/gate/apps/bikeservice/roles", ex -> {
            requests.incrementAndGet();
            byte[] out = (body.get() == null ? "" : body.get()).getBytes(StandardCharsets.US_ASCII);
            ex.getResponseHeaders().add("Content-Type", "application/jwt");
            ex.sendResponseHeaders(status.get(), out.length == 0 ? -1 : out.length);
            try (OutputStream os = ex.getResponseBody()) {
                os.write(out);
            }
        });
        gate.start();
    }

    @AfterEach
    void stop() {
        if (catalog != null) {
            catalog.stop();
        }
        gate.stop(0);
    }

    private GateRoleCatalog catalog(List<String> handled) {
        return catalog(handled, Clock.systemUTC());
    }

    private GateRoleCatalog catalog(List<String> handled, Clock clk) {
        GateAuthProperties props = new GateAuthProperties("bikeservice", "gate", List.of("http://localhost"),
                List.of("/api/**"), Ed25519Keys.toPem(GATE_KEY.publicKey()), null, List.of("admin"), null, "/auth",
                false, Duration.ofSeconds(30),
                new GateAuthProperties.Edge(true, "X-Gate-Assertion"),
                new GateAuthProperties.Direct(false, null, Duration.ofDays(30), Duration.ofHours(24), Duration.ofHours(1)),
                new GateAuthProperties.Local(false, List.of(), List.of(), Duration.ofHours(12), 5, Duration.ofMinutes(15)),
                new GateAuthProperties.Roles(true, "http://127.0.0.1:" + gate.getAddress().getPort(),
                        Duration.ofMinutes(10), handled, true));
        catalog = new GateRoleCatalog(new GateAuthSettings(props), e -> events.add((GateRolesChangedEvent) e), clk);
        return catalog;
    }

    private static String signed(long rv, String... codes) {
        List<RoleCatalog.Role> roles = java.util.Arrays.stream(codes)
                .map(c -> new RoleCatalog.Role(c, c.toUpperCase(), null, c.equals("admin"))).toList();
        return GATE.signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", rv, roles, Instant.now()));
    }

    @Test
    void newerCatalogsAreTakenOverAndAnnounced() throws Exception {
        GateRoleCatalog c = catalog(List.of());
        assertThat(c.current()).isEmpty();
        assertThat(c.displayName("editor")).isEqualTo("editor");

        body.set(signed(3, "admin", "editor"));
        assertThat(c.refresh()).isTrue();
        assertThat(c.current().orElseThrow().catalogVersion()).isEqualTo(3);
        assertThat(c.displayName("editor")).isEqualTo("EDITOR");
        assertThat(events).hasSize(1);
        assertThat(events.getFirst().previous()).isNull();

        body.set(signed(4, "admin", "editor", "viewer"));
        assertThat(c.refresh()).isTrue();
        assertThat(events).hasSize(2);
        assertThat(events.get(1).previous().catalogVersion()).isEqualTo(3);
        assertThat(events.get(1).current().find("viewer")).isNotNull();
    }

    @Test
    void anOlderCatalogNeverReplacesANewerOne() throws Exception {
        GateRoleCatalog c = catalog(List.of());
        body.set(signed(5, "admin"));
        c.refresh();
        body.set(signed(2, "admin", "hacker"));
        assertThat(c.refresh()).isFalse();
        assertThat(c.current().orElseThrow().catalogVersion()).isEqualTo(5);
        assertThat(events).hasSize(1);
    }

    @Test
    void theLastCatalogStaysWhileTheGateIsDownOrAnswersGarbage() throws Exception {
        GateRoleCatalog c = catalog(List.of());
        body.set(signed(1, "admin"));
        c.refresh();

        status.set(503);
        assertThatThrownBy(c::refresh).isInstanceOf(IOException.class);
        status.set(200);
        body.set(new TokenSigner(GateSigningKey.generate())
                .signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 9, List.of(), Instant.now())));
        assertThatThrownBy(c::refresh).isInstanceOf(TokenValidationException.class);
        assertThat(c.current().orElseThrow().catalogVersion()).isEqualTo(1);
    }

    @Test
    void aTokenWithANewerVersionTriggersAFetchAtMostOncePerMinute() throws Exception {
        body.set(signed(1, "admin"));
        GateRoleCatalog c = catalog(List.of(), clock);
        c.start();                                   // first fetch at start
        waitFor(() -> c.current().isPresent());
        int afterStart = requests.get();

        c.versionSeen(1L);                           // same version: nothing to do
        c.versionSeen(null);                         // gates before 0.3.0 send no rv
        body.set(signed(2, "admin", "editor"));
        c.versionSeen(2L);                           // newer, but the start fetch was less than a minute ago
        Thread.sleep(300);
        assertThat(requests.get()).isEqualTo(afterStart);

        clock.advance(Duration.ofSeconds(61));
        c.versionSeen(2L);                           // now it fetches
        waitFor(() -> c.current().orElseThrow().catalogVersion() == 2);
        assertThat(events).hasSize(2);
    }

    /** A clock the test moves forward. */
    private static final class TestClock extends Clock {
        private volatile Instant now = Instant.now();

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final TestClock clock = new TestClock();

    @Test
    void settingsNeedAGateUrl() {
        GateAuthProperties props = new GateAuthProperties("bikeservice", "gate", List.of("https://192.168.1.50:8443"),
                List.of("/api/**"), Ed25519Keys.toPem(GATE_KEY.publicKey()), null, List.of(), null, "/auth",
                true, Duration.ofSeconds(30), new GateAuthProperties.Edge(true, "X-Gate-Assertion"),
                new GateAuthProperties.Direct(false, null, Duration.ofDays(30), Duration.ofHours(24), Duration.ofHours(1)),
                new GateAuthProperties.Local(false, List.of(), List.of(), Duration.ofHours(12), 5, Duration.ofMinutes(15)),
                new GateAuthProperties.Roles(true, null, Duration.ofMinutes(10), List.of(), true));
        assertThatThrownBy(() -> new GateAuthSettings(props))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("gate.auth.roles.enabled");
    }

    private static void waitFor(java.util.function.BooleanSupplier condition) throws InterruptedException {
        for (int i = 0; i < 100 && !condition.getAsBoolean(); i++) {
            Thread.sleep(50);
        }
        assertThat(condition.getAsBoolean()).isTrue();
    }
}
