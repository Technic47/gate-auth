package io.github.technic47.gateauth.core;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;

/**
 * The gate's signing key: private and public half with its {@code kid}. Lives only in GateService.
 *
 * <p>Stored as a private JWK ({@code kty=OKP, crv=Ed25519, x, d}). One file holds both halves, because the JDK
 * cannot derive an Ed25519 public key from the private one. {@link #toString()} never prints key material.
 *
 * @param kid        key id, the first {@value Ed25519Keys#KID_LENGTH} characters of the RFC 7638 thumbprint
 * @param privateKey Ed25519 private key; secret
 * @param publicKey  matching Ed25519 public key
 */
public record GateSigningKey(String kid, PrivateKey privateKey, PublicKey publicKey) {

    /**
     * Checks that all parts are present.
     *
     * @throws IllegalArgumentException if any part is {@code null}
     */
    public GateSigningKey {
        if (kid == null || privateKey == null || publicKey == null) {
            throw new IllegalArgumentException("kid, privateKey and publicKey are required");
        }
    }

    /**
     * Wraps a JDK key pair and computes its {@code kid}.
     *
     * @param pair Ed25519 key pair
     * @return the signing key
     */
    public static GateSigningKey of(KeyPair pair) {
        return new GateSigningKey(Ed25519Keys.kid(pair.getPublic()), pair.getPrivate(), pair.getPublic());
    }

    /**
     * Generates a new random signing key.
     *
     * @return a fresh Ed25519 signing key
     */
    public static GateSigningKey generate() {
        return of(Ed25519Keys.generate());
    }

    /**
     * Reads a private JWK as written by {@link #toPrivateJwk()} or {@link KeyTool}.
     *
     * @param json private JWK ({@code kty=OKP, crv=Ed25519, x, d})
     * @return the signing key
     * @throws IllegalArgumentException if the JSON is not an Ed25519 private JWK
     */
    public static GateSigningKey fromPrivateJwk(String json) {
        Map<String, Object> jwk = Json.parseObject(json.trim());
        PublicKey pub = Ed25519Keys.publicFromJwk(jwk);
        PrivateKey priv = Ed25519Keys.privateFromJwk(jwk);
        return new GateSigningKey(Ed25519Keys.kid(pub), priv, pub);
    }

    /**
     * Serializes both halves as a private JWK. The result is secret.
     *
     * @return private JWK as one line of JSON
     */
    public String toPrivateJwk() {
        return Json.write(Ed25519Keys.toPrivateJwk(publicKey, privateKey));
    }

    @Override
    public String toString() {
        return "GateSigningKey[kid=" + kid + "]"; // never print key material
    }
}
