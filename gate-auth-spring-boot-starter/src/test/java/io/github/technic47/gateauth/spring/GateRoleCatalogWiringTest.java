package io.github.technic47.gateauth.spring;

import com.sun.net.httpserver.HttpServer;
import io.github.technic47.gateauth.core.Ed25519Keys;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.RoleCatalog;
import io.github.technic47.gateauth.core.TokenSigner;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code gate.auth.roles.*} binds, the catalog bean starts with the app and fetches from the gate. */
@SpringBootTest
class GateRoleCatalogWiringTest {

    private static final GateSigningKey GATE_KEY = GateSigningKey.generate();
    private static final HttpServer GATE = fakeGate();

    private static HttpServer fakeGate() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
            server.createContext("/.well-known/gate/apps/bikeservice/roles", ex -> {
                byte[] out = new TokenSigner(GATE_KEY).signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 4,
                        List.of(new RoleCatalog.Role("viewer", "Viewer", null, true)), Instant.now()))
                        .getBytes(StandardCharsets.US_ASCII);
                ex.sendResponseHeaders(200, out.length);
                try (OutputStream os = ex.getResponseBody()) {
                    os.write(out);
                }
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("gate.auth.app-name", () -> "bikeservice");
        r.add("gate.auth.public-urls", () -> "http://localhost");
        r.add("gate.auth.public-keys", () -> Ed25519Keys.toPem(GATE_KEY.publicKey()));
        r.add("gate.auth.cookie-secure", () -> "false");
        r.add("gate.auth.edge.enabled", () -> "true");
        r.add("gate.auth.roles.enabled", () -> "true");
        r.add("gate.auth.roles.gate-url", () -> "http://127.0.0.1:" + GATE.getAddress().getPort());
        r.add("gate.auth.roles.refresh", () -> "5m");
        r.add("gate.auth.roles.handled", () -> "viewer,editor");
    }

    @AfterAll
    static void stopGate() {
        GATE.stop(0);
    }

    @Autowired
    GateRoleCatalog catalog;

    @Autowired
    GateAuthSettings settings;

    @Test
    void catalogIsBoundStartedAndFetched() throws InterruptedException {
        assertThat(settings.props().roles().handled()).containsExactly("viewer", "editor");
        assertThat(settings.props().roles().refresh()).hasMinutes(5);
        for (int i = 0; i < 100 && catalog.current().isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertThat(catalog.current()).isPresent();
        assertThat(catalog.current().get().catalogVersion()).isEqualTo(4);
        assertThat(catalog.displayName("viewer")).isEqualTo("Viewer");
    }
}
