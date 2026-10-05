package io.github.technic47.gateauth.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Ed25519 key helpers using only the JDK: raw bytes, JDK key objects, PEM, JWK (RFC 8037) and thumbprint
 * (RFC 7638).
 *
 * <p>All methods throw {@link IllegalArgumentException} for input that is not a well-formed Ed25519 key.
 */
public final class Ed25519Keys {

    /** DER prefix of an X.509 SubjectPublicKeyInfo for Ed25519; followed by the 32-byte public key. */
    private static final byte[] X509_PREFIX = hex("302a300506032b6570032100");
    /** DER prefix of a PKCS#8 PrivateKeyInfo (v1) for Ed25519; followed by the 32-byte seed. */
    private static final byte[] PKCS8_PREFIX = hex("302e020100300506032b657004220420");

    /** Length of the {@code kid} taken from the thumbprint (spec §3). */
    public static final int KID_LENGTH = 16;

    private Ed25519Keys() {
    }

    /**
     * Generates a random key pair.
     *
     * @return a new Ed25519 key pair
     */
    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 not available in this JDK", e);
        }
    }

    // ---------------------------------------------------------------- raw

    /**
     * Extracts the 32-byte public key.
     *
     * @param key Ed25519 public key
     * @return the raw public key (the JWK {@code x} value, before base64url)
     */
    public static byte[] rawPublic(PublicKey key) {
        byte[] der = key.getEncoded();
        if (!"Ed25519".equals(key.getAlgorithm()) && !"EdDSA".equals(key.getAlgorithm())) {
            throw new IllegalArgumentException("Not an Ed25519 key: " + key.getAlgorithm());
        }
        if (der.length != X509_PREFIX.length + 32 || !startsWith(der, X509_PREFIX)) {
            throw new IllegalArgumentException("Not an Ed25519 public key");
        }
        return Arrays.copyOfRange(der, X509_PREFIX.length, der.length);
    }

    /**
     * Builds a public key from its 32 raw bytes.
     *
     * @param raw 32-byte public key
     * @return the JDK key
     */
    public static PublicKey publicFromRaw(byte[] raw) {
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        return publicFromX509(concat(X509_PREFIX, raw));
    }

    /**
     * Extracts the 32-byte private key (seed).
     *
     * @param key Ed25519 private key
     * @return the raw seed (the JWK {@code d} value, before base64url); secret
     */
    public static byte[] rawPrivate(PrivateKey key) {
        if (key instanceof EdECPrivateKey ed) {
            return ed.getBytes().orElseThrow(() -> new IllegalArgumentException("Private key bytes not extractable"));
        }
        throw new IllegalArgumentException("Not an Ed25519 private key");
    }

    /**
     * Builds a private key from its 32-byte seed.
     *
     * @param seed 32-byte private key
     * @return the JDK key
     */
    public static PrivateKey privateFromRaw(byte[] seed) {
        if (seed.length != 32) {
            throw new IllegalArgumentException("Ed25519 private key must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seed)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid Ed25519 private key", e);
        }
    }

    // ---------------------------------------------------------------- PEM

    /**
     * Writes a public key as PEM ({@code -----BEGIN PUBLIC KEY-----}, X.509 SubjectPublicKeyInfo).
     *
     * @param key Ed25519 public key
     * @return PEM text
     */
    public static String toPem(PublicKey key) {
        return pem("PUBLIC KEY", concat(X509_PREFIX, rawPublic(key)));
    }

    /**
     * Writes a private key as PEM ({@code -----BEGIN PRIVATE KEY-----}, PKCS#8). The result is secret.
     *
     * @param key Ed25519 private key
     * @return PEM text
     */
    public static String toPem(PrivateKey key) {
        return pem("PRIVATE KEY", concat(PKCS8_PREFIX, rawPrivate(key)));
    }

    /**
     * Reads a public key from PEM.
     *
     * @param pem text containing one {@code PUBLIC KEY} block
     * @return the JDK key
     */
    public static PublicKey publicFromPem(String pem) {
        return publicFromX509(pemBody(pem, "PUBLIC KEY"));
    }

    /**
     * Reads a private key from PEM.
     *
     * @param pem text containing one PKCS#8 {@code PRIVATE KEY} block
     * @return the JDK key
     */
    public static PrivateKey privateFromPem(String pem) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(pemBody(pem, "PRIVATE KEY")));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid Ed25519 private key PEM", e);
        }
    }

    // ---------------------------------------------------------------- JWK

    /**
     * Builds a public JWK: {@code {"kty":"OKP","crv":"Ed25519","x":…,"kid":…,"alg":"EdDSA","use":"sig"}}.
     *
     * @param key Ed25519 public key
     * @return the JWK as a mutable map, ready for {@link Json#write(Object)}
     */
    public static Map<String, Object> toPublicJwk(PublicKey key) {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "OKP");
        jwk.put("crv", "Ed25519");
        jwk.put("x", Base64Url.encode(rawPublic(key)));
        jwk.put("kid", kid(key));
        jwk.put("alg", "EdDSA");
        jwk.put("use", "sig");
        return jwk;
    }

    /**
     * Builds a private JWK: the public JWK plus {@code d}. Secret: only for the gate.
     *
     * @param publicKey  Ed25519 public key
     * @param privateKey matching Ed25519 private key
     * @return the JWK as a mutable map
     */
    public static Map<String, Object> toPrivateJwk(PublicKey publicKey, PrivateKey privateKey) {
        Map<String, Object> jwk = toPublicJwk(publicKey);
        jwk.put("d", Base64Url.encode(rawPrivate(privateKey)));
        return jwk;
    }

    /**
     * Reads the public key from a JWK ({@code kty=OKP}, {@code crv=Ed25519}, {@code x}).
     *
     * @param jwk parsed JWK
     * @return the JDK key
     */
    public static PublicKey publicFromJwk(Map<String, Object> jwk) {
        if (!"OKP".equals(jwk.get("kty")) || !"Ed25519".equals(jwk.get("crv"))) {
            throw new IllegalArgumentException("JWK is not an Ed25519 OKP key");
        }
        Object x = jwk.get("x");
        if (!(x instanceof String xs)) {
            throw new IllegalArgumentException("JWK has no 'x'");
        }
        return publicFromRaw(Base64Url.decode(xs));
    }

    /**
     * Reads the private key from a private JWK (also checks {@code kty}, {@code crv}, {@code x}).
     *
     * @param jwk parsed private JWK
     * @return the JDK key
     */
    public static PrivateKey privateFromJwk(Map<String, Object> jwk) {
        publicFromJwk(jwk); // validates kty/crv/x
        Object d = jwk.get("d");
        if (!(d instanceof String ds)) {
            throw new IllegalArgumentException("JWK has no 'd' (not a private key)");
        }
        return privateFromRaw(Base64Url.decode(ds));
    }

    // ---------------------------------------------------------------- kid

    /**
     * Computes the RFC 7638 JWK thumbprint (SHA-256).
     *
     * @param key Ed25519 public key
     * @return base64url thumbprint (43 characters)
     */
    public static String thumbprint(PublicKey key) {
        String canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Base64Url.encode(rawPublic(key)) + "\"}";
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8));
            return Base64Url.encode(hash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Computes the key id (spec §3): the first {@value #KID_LENGTH} characters of the thumbprint.
     *
     * @param key Ed25519 public key
     * @return the {@code kid}
     */
    public static String kid(PublicKey key) {
        return thumbprint(key).substring(0, KID_LENGTH);
    }

    // ---------------------------------------------------------------- internals

    private static PublicKey publicFromX509(byte[] der) {
        if (der.length != X509_PREFIX.length + 32 || !startsWith(der, X509_PREFIX)) {
            throw new IllegalArgumentException("Not an Ed25519 public key");
        }
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Invalid Ed25519 public key", e);
        }
    }

    private static String pem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    private static byte[] pemBody(String pem, String type) {
        String begin = "-----BEGIN " + type + "-----";
        String end = "-----END " + type + "-----";
        int b = pem.indexOf(begin);
        int e = pem.indexOf(end);
        if (b < 0 || e < b) {
            throw new IllegalArgumentException("Not a PEM " + type);
        }
        String body = pem.substring(b + begin.length(), e).replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static boolean startsWith(byte[] data, byte[] prefix) {
        return data.length >= prefix.length && Arrays.equals(data, 0, prefix.length, prefix, 0, prefix.length);
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}
