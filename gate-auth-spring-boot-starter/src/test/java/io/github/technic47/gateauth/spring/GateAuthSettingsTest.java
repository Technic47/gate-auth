package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.Ed25519Keys;
import io.github.technic47.gateauth.core.GateSigningKey;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GateAuthSettingsTest {

    private static final String KEY = Ed25519Keys.toPem(GateSigningKey.generate().publicKey());

    private static GateAuthProperties props(boolean edge, boolean direct, boolean local, String keys, String secret,
                                            List<String> networks) {
        return new GateAuthProperties("bikeservice", "gate", List.of("https://192.168.1.50:8443"), List.of("/api/**"),
                keys, null, List.of(), secret, "/auth", true, Duration.ofSeconds(30),
                new GateAuthProperties.Edge(edge, "X-Gate-Assertion"),
                new GateAuthProperties.Direct(direct, "https://144.31.187.7", Duration.ofDays(30), Duration.ofHours(24),
                        Duration.ofHours(1)),
                new GateAuthProperties.Local(local, networks, List.of(), Duration.ofHours(12), 5, Duration.ofMinutes(15)));
    }

    @Test
    void noModeFailsFast() {
        assertThatThrownBy(() -> new GateAuthSettings(props(false, false, false, KEY, null, null)))
                .hasMessageContaining("no mode enabled");
    }

    @Test
    void edgeWithoutKeyFailsFast() {
        assertThatThrownBy(() -> new GateAuthSettings(props(true, false, false, null, null, null)))
                .hasMessageContaining("public-keys");
    }

    @Test
    void directWithoutSecretFailsFast() {
        assertThatThrownBy(() -> new GateAuthSettings(props(false, true, false, KEY, "short", null)))
                .hasMessageContaining("local-secret");
    }

    @Test
    void localWithoutNetworksOrUsersFailsFast() {
        assertThatThrownBy(() -> new GateAuthSettings(props(false, false, true, null, null, List.of())))
                .hasMessageContaining("allowed-networks")
                .hasMessageContaining("users");
    }

    @Test
    void edgeOnlyIsValid() {
        GateAuthSettings s = new GateAuthSettings(props(true, false, false, KEY, null, null));
        assertThat(s.sessionCookieName()).isEqualTo("BIKESERVICE_SESSION");
        assertThat(s.isAllowedOrigin("https://192.168.1.50:8443")).isTrue();
        assertThat(s.isAllowedOrigin("https://192.168.1.50:8444")).isFalse();
        assertThat(s.isAllowedOrigin("https://192.168.1.50:8443.evil.com")).isFalse();
    }

    @Test
    void returnPathMustBeRelative() {
        assertThat(GateAuthSettings.safeReturnPath("/bikes?x=1")).isEqualTo("/bikes?x=1");
        for (String bad : List.of("https://evil.com", "//evil.com", "/\\evil.com", "bikes", "/a b", "/a\nb")) {
            assertThat(GateAuthSettings.safeReturnPath(bad)).as(bad).isEqualTo("/");
        }
    }
}
