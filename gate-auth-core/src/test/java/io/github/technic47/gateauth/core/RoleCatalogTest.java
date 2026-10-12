package io.github.technic47.gateauth.core;

import io.github.technic47.gateauth.core.TokenValidationException.Reason;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleCatalogTest {

    private static final Instant NOW = Instant.parse("2026-10-12T12:00:00Z");

    private final GateSigningKey key = GateSigningKey.generate();
    private final TokenSigner signer = new TokenSigner(key);
    private final TokenVerifier verifier = verifier(NOW);

    private TokenVerifier verifier(Instant now) {
        return new TokenVerifier(GateKeySet.of(key.publicKey()), "gate", "bikeservice", Duration.ofSeconds(30),
                Clock.fixed(now, ZoneOffset.UTC));
    }

    private static final List<RoleCatalog.Role> ROLES = List.of(
            new RoleCatalog.Role("admin", "Administrator", "Everything", true),
            new RoleCatalog.Role("editor", "Editor", null, false));

    @Test
    void signedCatalogRoundTrips() throws Exception {
        String token = signer.signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 7, ROLES, NOW));
        RoleCatalog c = verifier.verifyRoleCatalog(token);
        assertThat(c.catalogVersion()).isEqualTo(7);
        assertThat(c.roles()).containsExactlyElementsOf(ROLES);
        assertThat(c.find("editor").global()).isFalse();
        assertThat(c.find("admin").description()).isEqualTo("Everything");
        assertThat(c.find("viewer")).isNull();
        assertThat(c.expiresAt() - c.issuedAt()).isEqualTo(86_400);
    }

    @Test
    void catalogAndTokensCantBeSwapped() {
        String catalog = signer.signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 1, ROLES, NOW));
        assertThatThrownBy(() -> verifier.verifyAssertion(catalog))
                .isInstanceOfSatisfying(TokenValidationException.class, e -> assertThat(e.reason()).isEqualTo(Reason.WRONG_TYPE));
        String assertion = signer.sign(TokenType.ASSERTION, GateClaims.builder().subject("1").audience("bikeservice")
                .issuedAt(NOW).build(TokenType.ASSERTION));
        assertThatThrownBy(() -> verifier.verifyRoleCatalog(assertion))
                .isInstanceOfSatisfying(TokenValidationException.class, e -> assertThat(e.reason()).isEqualTo(Reason.WRONG_TYPE));
        assertThatThrownBy(() -> signer.sign(TokenType.ROLES, GateClaims.builder().subject("1").audience("x")
                .issuedAt(NOW).build(TokenType.ASSERTION))).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void catalogForAnotherAppIsRejected() {
        String token = signer.signRoleCatalog(RoleCatalog.issue("gate", "fashionmark", 1, ROLES, NOW));
        assertThatThrownBy(() -> verifier.verifyRoleCatalog(token))
                .isInstanceOfSatisfying(TokenValidationException.class, e -> assertThat(e.reason()).isEqualTo(Reason.WRONG_AUDIENCE));
    }

    @Test
    void expiredOrTooLongLivedCatalogIsRejected() {
        String token = signer.signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 1, ROLES, NOW));
        assertThatThrownBy(() -> verifier(NOW.plus(Duration.ofDays(2))).verifyRoleCatalog(token))
                .isInstanceOfSatisfying(TokenValidationException.class, e -> assertThat(e.reason()).isEqualTo(Reason.EXPIRED));
        long iat = NOW.getEpochSecond();
        RoleCatalog tooLong = new RoleCatalog(1, "gate", "bikeservice", iat, iat + 8 * 86_400, 1, ROLES);
        assertThatThrownBy(() -> signer.signRoleCatalog(tooLong)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void foreignKeyIsRejected() {
        String token = new TokenSigner(GateSigningKey.generate())
                .signRoleCatalog(RoleCatalog.issue("gate", "bikeservice", 1, ROLES, NOW));
        assertThatThrownBy(() -> verifier.verifyRoleCatalog(token)).isInstanceOf(TokenValidationException.class);
    }

    @Test
    void roleCodesAreChecked() {
        assertThatThrownBy(() -> new RoleCatalog.Role("Editor", "Editor", null, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RoleCatalog.Role("1st", "First", null, false))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tokensCarryTheCatalogVersion() throws Exception {
        String token = signer.sign(TokenType.ASSERTION, GateClaims.builder().subject("1").audience("bikeservice")
                .roles(List.of("editor", "viewer")).roleVersion(12L).issuedAt(NOW).build(TokenType.ASSERTION));
        GateClaims claims = verifier.verifyAssertion(token);
        assertThat(claims.roleVersion()).isEqualTo(12L);
        assertThat(claims.roles()).containsExactly("editor", "viewer");

        // tokens from gates before 0.3.0 have no rv
        String old = signer.sign(TokenType.ASSERTION, GateClaims.builder().subject("1").audience("bikeservice")
                .issuedAt(NOW).build(TokenType.ASSERTION));
        assertThat(verifier.verifyAssertion(old).roleVersion()).isNull();
    }
}
