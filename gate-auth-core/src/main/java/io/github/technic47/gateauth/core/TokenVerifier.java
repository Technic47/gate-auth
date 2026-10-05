package io.github.technic47.gateauth.core;

import io.github.technic47.gateauth.core.TokenValidationException.Reason;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Verifies Gate Auth v1 tokens exactly as spec §4.3 lists, in that order. Thread-safe.
 *
 * Replay protection ({@code jti}) is not done here; use {@link ReplayGuard} for handoff tokens.
 */
public final class TokenVerifier {

    /** Upper bound for {@code exp - iat} accepted from the gate. */
    public static final long MAX_LIFETIME_SECONDS = 300;
    /** Tokens longer than this are rejected before any parsing. */
    public static final int MAX_TOKEN_LENGTH = 8192;

    private final GateKeySet keys;
    private final String issuer;
    private final String audience;
    private final long skewSeconds;
    private final Clock clock;

    /**
     * Creates a verifier.
     *
     * @param keys     the gate's public keys
     * @param issuer   expected {@code iss}
     * @param audience this app's app-name, expected {@code aud}
     * @param skew     allowed clock difference to the gate
     * @param clock    source of the current time
     */
    public TokenVerifier(GateKeySet keys, String issuer, String audience, Duration skew, Clock clock) {
        this.keys = Objects.requireNonNull(keys, "keys");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.audience = Objects.requireNonNull(audience, "audience");
        this.skewSeconds = skew.toSeconds();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Creates a verifier with 30 s clock skew and the system UTC clock.
     *
     * @param keys     the gate's public keys
     * @param issuer   expected {@code iss}
     * @param audience this app's app-name, expected {@code aud}
     */
    public TokenVerifier(GateKeySet keys, String issuer, String audience) {
        this(keys, issuer, audience, Duration.ofSeconds(30), Clock.systemUTC());
    }

    /**
     * The app-name tokens must be issued for.
     *
     * @return expected {@code aud}
     */
    public String audience() {
        return audience;
    }

    /**
     * Verifies an edge-mode assertion ({@code X-Gate-Assertion}).
     *
     * @param token the header value
     * @return verified claims
     * @throws TokenValidationException if any check of spec §4.3 fails
     */
    public GateClaims verifyAssertion(String token) throws TokenValidationException {
        return verify(token, TokenType.ASSERTION, null);
    }

    /**
     * Verifies a direct-mode handoff token and binds it to the nonce the app stored when the login started.
     * Single use ({@code jti}) is not checked here; use {@link ReplayGuard}.
     *
     * @param token         the posted {@code id_token}
     * @param expectedNonce the nonce the app sent to the gate
     * @return verified claims
     * @throws TokenValidationException if any check of spec §4.3 fails or the nonce differs
     */
    public GateClaims verifyHandoff(String token, String expectedNonce) throws TokenValidationException {
        Objects.requireNonNull(expectedNonce, "expectedNonce");
        return verify(token, TokenType.HANDOFF, expectedNonce);
    }

    private GateClaims verify(String token, TokenType expectedType, String expectedNonce) throws TokenValidationException {
        // 1. structure + algorithm
        if (token == null || token.isEmpty() || token.length() > MAX_TOKEN_LENGTH) {
            throw new TokenValidationException(Reason.MALFORMED, "empty or too long");
        }
        String[] parts = token.split("\\.", -1);
        if (parts.length != 3) {
            throw new TokenValidationException(Reason.MALFORMED, "expected 3 parts");
        }
        Map<String, Object> header;
        Map<String, Object> payload;
        byte[] signature;
        try {
            header = Json.parseObject(Base64Url.decodeToString(parts[0]));
            payload = Json.parseObject(Base64Url.decodeToString(parts[1]));
            signature = Base64Url.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new TokenValidationException(Reason.MALFORMED, e.getMessage());
        }
        if (!"EdDSA".equals(header.get("alg"))) {
            throw new TokenValidationException(Reason.UNSUPPORTED_ALGORITHM, String.valueOf(header.get("alg")));
        }
        if (header.containsKey("crit")) {
            throw new TokenValidationException(Reason.MALFORMED, "crit header not supported");
        }

        // 2. type
        if (!expectedType.typ().equals(header.get("typ"))) {
            throw new TokenValidationException(Reason.WRONG_TYPE, "expected " + expectedType.typ());
        }

        // 3. key + signature
        if (!(header.get("kid") instanceof String kid)) {
            throw new TokenValidationException(Reason.UNKNOWN_KEY, "no kid");
        }
        PublicKey key = keys.find(kid)
                .orElseThrow(() -> new TokenValidationException(Reason.UNKNOWN_KEY, "kid " + kid));
        if (!signatureValid(key, parts[0] + "." + parts[1], signature)) {
            throw new TokenValidationException(Reason.BAD_SIGNATURE, "kid " + kid);
        }

        GateClaims claims;
        try {
            claims = GateClaims.fromMap(payload);
        } catch (IllegalArgumentException e) {
            throw new TokenValidationException(Reason.INVALID_CLAIMS, e.getMessage());
        }

        // 4. version, issuer, audience
        if (claims.version() != GateClaims.VERSION) {
            throw new TokenValidationException(Reason.UNSUPPORTED_VERSION, "v=" + claims.version());
        }
        if (!issuer.equals(claims.issuer())) {
            throw new TokenValidationException(Reason.WRONG_ISSUER, claims.issuer());
        }
        if (!audience.equals(claims.audience())) {
            throw new TokenValidationException(Reason.WRONG_AUDIENCE, claims.audience());
        }

        // 5. time
        long now = clock.instant().getEpochSecond();
        if (claims.expiresAt() <= now - skewSeconds) {
            throw new TokenValidationException(Reason.EXPIRED, "exp=" + claims.expiresAt() + " now=" + now);
        }
        if (claims.issuedAt() >= now + skewSeconds) {
            throw new TokenValidationException(Reason.NOT_YET_VALID, "iat=" + claims.issuedAt() + " now=" + now);
        }
        long lifetime = claims.expiresAt() - claims.issuedAt();
        if (lifetime <= 0 || lifetime > MAX_LIFETIME_SECONDS) {
            throw new TokenValidationException(Reason.LIFETIME_TOO_LONG, lifetime + " s");
        }

        // 6. nonce (handoff only); jti replay is checked by the caller
        if (expectedNonce != null) {
            String nonce = claims.nonce();
            if (nonce == null || !MessageDigest.isEqual(
                    nonce.getBytes(StandardCharsets.UTF_8), expectedNonce.getBytes(StandardCharsets.UTF_8))) {
                throw new TokenValidationException(Reason.NONCE_MISMATCH, "nonce does not match");
            }
        }

        // 7. remaining required claims
        if (claims.tokenId() == null || claims.tokenId().isEmpty()) {
            throw new TokenValidationException(Reason.INVALID_CLAIMS, "jti missing");
        }
        if (claims.gateRole() == null || claims.gateRole().isEmpty()) {
            throw new TokenValidationException(Reason.INVALID_CLAIMS, "gate_role missing");
        }
        return claims;
    }

    private static boolean signatureValid(PublicKey key, String signingInput, byte[] signature) {
        if (signature.length != 64) {
            return false;
        }
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initVerify(key);
            sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return sig.verify(signature);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
