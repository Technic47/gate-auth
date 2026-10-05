package io.github.technic47.gateauth.core;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Ed25519KeysTest {

    // RFC 8037 Appendix A
    private static final String D = "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A";
    private static final String X = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    private static final String THUMBPRINT = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
    private static final String SIGNING_INPUT = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc";
    private static final String SIGNATURE =
            "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

    @Test
    void rfc8037ThumbprintMatches() {
        PublicKey key = Ed25519Keys.publicFromRaw(Base64Url.decode(X));
        assertThat(Ed25519Keys.thumbprint(key)).isEqualTo(THUMBPRINT);
        assertThat(Ed25519Keys.kid(key)).isEqualTo(THUMBPRINT.substring(0, 16));
    }

    @Test
    void rfc8037SignatureIsReproducedAndVerifies() throws Exception {
        PrivateKey priv = Ed25519Keys.privateFromRaw(Base64Url.decode(D));
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(priv);
        s.update(SIGNING_INPUT.getBytes(StandardCharsets.US_ASCII));
        assertThat(Base64Url.encode(s.sign())).isEqualTo(SIGNATURE);

        Signature v = Signature.getInstance("Ed25519");
        v.initVerify(Ed25519Keys.publicFromRaw(Base64Url.decode(X)));
        v.update(SIGNING_INPUT.getBytes(StandardCharsets.US_ASCII));
        assertThat(v.verify(Base64Url.decode(SIGNATURE))).isTrue();
    }

    @Test
    void pemRoundTrip() {
        GateSigningKey key = GateSigningKey.generate();
        PublicKey pub = Ed25519Keys.publicFromPem(Ed25519Keys.toPem(key.publicKey()));
        PrivateKey priv = Ed25519Keys.privateFromPem(Ed25519Keys.toPem(key.privateKey()));
        assertThat(Ed25519Keys.rawPublic(pub)).isEqualTo(Ed25519Keys.rawPublic(key.publicKey()));
        assertThat(Ed25519Keys.rawPrivate(priv)).isEqualTo(Ed25519Keys.rawPrivate(key.privateKey()));
    }

    @Test
    void privateJwkRoundTrip() {
        GateSigningKey key = GateSigningKey.generate();
        GateSigningKey back = GateSigningKey.fromPrivateJwk(key.toPrivateJwk());
        assertThat(back.kid()).isEqualTo(key.kid());
        assertThat(Ed25519Keys.rawPrivate(back.privateKey())).isEqualTo(Ed25519Keys.rawPrivate(key.privateKey()));
        assertThat(back.toString()).doesNotContain(Base64Url.encode(Ed25519Keys.rawPrivate(key.privateKey())));
    }

    @Test
    void keySetParsesPemBlocksJwkAndJwks() {
        GateSigningKey a = GateSigningKey.generate();
        GateSigningKey b = GateSigningKey.generate();

        String twoPems = Ed25519Keys.toPem(a.publicKey()) + "\n" + Ed25519Keys.toPem(b.publicKey());
        assertThat(GateKeySet.parse(twoPems).asMap()).containsOnlyKeys(a.kid(), b.kid());

        String jwk = Json.write(Ed25519Keys.toPublicJwk(a.publicKey()));
        assertThat(GateKeySet.parse(jwk).asMap()).containsOnlyKeys(a.kid());

        String jwks = GateKeySet.of(a.publicKey(), b.publicKey()).toJwks();
        assertThat(GateKeySet.parse(jwks).asMap()).containsOnlyKeys(a.kid(), b.kid());
    }

    @Test
    void jwkWithWrongKidIsRejected() {
        GateSigningKey a = GateSigningKey.generate();
        Map<String, Object> jwk = Ed25519Keys.toPublicJwk(a.publicKey());
        jwk.put("kid", "typo");
        assertThatThrownBy(() -> GateKeySet.parse(Json.write(jwk))).hasMessageContaining("does not match");
    }

    @Test
    void publicJwksNeverContainsPrivatePart() {
        GateSigningKey a = GateSigningKey.generate();
        assertThat(GateKeySet.of(a.publicKey()).toJwks()).doesNotContain("\"d\"");
    }
}
