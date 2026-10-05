package io.github.technic47.gateauth.core;

import io.github.technic47.gateauth.core.TokenValidationException.Reason;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenVerifierTest {

    private static final Instant NOW = Instant.parse("2026-10-05T12:00:00Z");

    private final GateSigningKey key = GateSigningKey.generate();
    private final TokenSigner signer = new TokenSigner(key);
    private final TokenVerifier verifier = verifier(Clock.fixed(NOW, ZoneOffset.UTC));

    private TokenVerifier verifier(Clock clock) {
        return new TokenVerifier(GateKeySet.of(key.publicKey()), "gate", "bikeservice", Duration.ofSeconds(30), clock);
    }

    private GateClaims.Builder claims() {
        return GateClaims.builder()
                .subject("42").preferredUsername("technic").audience("bikeservice")
                .gateRole("ADMIN").roles(List.of("admin")).services(List.of("bikeservice", "fashionmark"))
                .issuedAt(NOW).sessionId("s1");
    }

    @Test
    void validAssertionIsAccepted() throws Exception {
        String token = signer.sign(TokenType.ASSERTION, claims().build(TokenType.ASSERTION));
        GateClaims c = verifier.verifyAssertion(token);
        assertThat(c.subject()).isEqualTo("42");
        assertThat(c.preferredUsername()).isEqualTo("technic");
        assertThat(c.roles()).containsExactly("admin");
        assertThat(c.services()).containsExactly("bikeservice", "fashionmark");
        assertThat(c.expiresAt() - c.issuedAt()).isEqualTo(60);
        assertThat(c.nonce()).isNull();
    }

    @Test
    void validHandoffIsAccepted() throws Exception {
        String token = signer.sign(TokenType.HANDOFF, claims().nonce("n-1").authTime(NOW).build(TokenType.HANDOFF));
        GateClaims c = verifier.verifyHandoff(token, "n-1");
        assertThat(c.nonce()).isEqualTo("n-1");
        assertThat(c.authTime()).isEqualTo(NOW.getEpochSecond());
    }

    @Test
    void handoffCannotBeUsedAsAssertionAndViceVersa() {
        String handoff = signer.sign(TokenType.HANDOFF, claims().nonce("n").build(TokenType.HANDOFF));
        String assertion = signer.sign(TokenType.ASSERTION, claims().build(TokenType.ASSERTION));
        assertReason(() -> verifier.verifyAssertion(handoff), Reason.WRONG_TYPE);
        assertReason(() -> verifier.verifyHandoff(assertion, "n"), Reason.WRONG_TYPE);
    }

    @Test
    void wrongNonceIsRejected() {
        String token = signer.sign(TokenType.HANDOFF, claims().nonce("n-1").build(TokenType.HANDOFF));
        assertReason(() -> verifier.verifyHandoff(token, "n-2"), Reason.NONCE_MISMATCH);
    }

    @Test
    void otherAudienceIsRejected() {
        String token = signer.sign(TokenType.ASSERTION, claims().audience("fashionmark").build(TokenType.ASSERTION));
        assertReason(() -> verifier.verifyAssertion(token), Reason.WRONG_AUDIENCE);
    }

    @Test
    void otherIssuerIsRejected() {
        String token = signer.sign(TokenType.ASSERTION, claims().issuer("evil").build(TokenType.ASSERTION));
        assertReason(() -> verifier.verifyAssertion(token), Reason.WRONG_ISSUER);
    }

    @Test
    void expiryRespectsSkew() throws Exception {
        String token = signer.sign(TokenType.ASSERTION, claims().build(TokenType.ASSERTION)); // exp = NOW + 60
        verifier(Clock.fixed(NOW.plusSeconds(85), ZoneOffset.UTC)).verifyAssertion(token);
        assertReason(() -> verifier(Clock.fixed(NOW.plusSeconds(90), ZoneOffset.UTC)).verifyAssertion(token),
                Reason.EXPIRED);
    }

    @Test
    void tokenFromTheFutureIsRejected() {
        String token = signer.sign(TokenType.ASSERTION, claims().issuedAt(NOW.plusSeconds(31)).build(TokenType.ASSERTION));
        assertReason(() -> verifier.verifyAssertion(token), Reason.NOT_YET_VALID);
    }

    @Test
    void signerRefusesLongLifetime() {
        assertThatThrownBy(() -> signer.sign(TokenType.ASSERTION, claims().lifetimeSeconds(3600).build(TokenType.ASSERTION)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tamperedPayloadIsRejected() {
        String token = signer.sign(TokenType.ASSERTION, claims().build(TokenType.ASSERTION));
        String[] p = token.split("\\.");
        Map<String, Object> payload = Json.parseObject(Base64Url.decodeToString(p[1]));
        payload.put("roles", List.of("admin", "root"));
        String forged = p[0] + "." + Base64Url.encode(Json.write(payload)) + "." + p[2];
        assertReason(() -> verifier.verifyAssertion(forged), Reason.BAD_SIGNATURE);
    }

    @Test
    void tokenFromAnotherKeyWithSameKidIsRejected() throws Exception {
        GateSigningKey other = GateSigningKey.generate();
        // Sign with another key but claim our kid.
        String header = Base64Url.encode("{\"alg\":\"EdDSA\",\"kid\":\"" + key.kid() + "\",\"typ\":\"gate-assertion+jwt\"}");
        String payload = Base64Url.encode(Json.write(claims().build(TokenType.ASSERTION).toMap()));
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(other.privateKey());
        s.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
        String token = header + "." + payload + "." + Base64Url.encode(s.sign());
        assertReason(() -> verifier.verifyAssertion(token), Reason.BAD_SIGNATURE);
    }

    @Test
    void unknownKidIsRejected() {
        String token = new TokenSigner(GateSigningKey.generate())
                .sign(TokenType.ASSERTION, claims().build(TokenType.ASSERTION));
        assertReason(() -> verifier.verifyAssertion(token), Reason.UNKNOWN_KEY);
    }

    @Test
    void algNoneAndOtherAlgorithmsAreRejected() {
        String payload = Base64Url.encode(Json.write(claims().build(TokenType.ASSERTION).toMap()));
        for (String alg : List.of("none", "HS256", "RS256")) {
            String header = Base64Url.encode("{\"alg\":\"" + alg + "\",\"kid\":\"" + key.kid() + "\",\"typ\":\"gate-assertion+jwt\"}");
            assertReason(() -> verifier.verifyAssertion(header + "." + payload + "."), Reason.UNSUPPORTED_ALGORITHM);
        }
    }

    @Test
    void otherVersionIsRejected() throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>(claims().build(TokenType.ASSERTION).toMap());
        payload.put("v", 2L);
        String header = Base64Url.encode("{\"alg\":\"EdDSA\",\"kid\":\"" + key.kid() + "\",\"typ\":\"gate-assertion+jwt\"}");
        String body = Base64Url.encode(Json.write(payload));
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(key.privateKey());
        s.update((header + "." + body).getBytes(StandardCharsets.US_ASCII));
        assertReason(() -> verifier.verifyAssertion(header + "." + body + "." + Base64Url.encode(s.sign())),
                Reason.UNSUPPORTED_VERSION);
    }

    @Test
    void garbageIsMalformed() {
        for (String t : List.of("", "a.b", "a.b.c.d", "!!!.###.$$$", "x".repeat(9000))) {
            assertReason(() -> verifier.verifyAssertion(t), Reason.MALFORMED);
        }
    }

    @Test
    void replayGuardAllowsOnlyFirstUse() {
        ReplayGuard guard = new ReplayGuard(Clock.fixed(NOW, ZoneOffset.UTC));
        assertThat(guard.firstUse("jti-1", NOW.getEpochSecond() + 120)).isTrue();
        assertThat(guard.firstUse("jti-1", NOW.getEpochSecond() + 120)).isFalse();
        assertThat(guard.firstUse("jti-2", NOW.getEpochSecond() + 120)).isTrue();
    }

    private interface Call {
        void run() throws Exception;
    }

    private static void assertReason(Call call, Reason reason) {
        assertThatThrownBy(call::run)
                .isInstanceOf(TokenValidationException.class)
                .extracting(e -> ((TokenValidationException) e).reason())
                .isEqualTo(reason);
    }
}
