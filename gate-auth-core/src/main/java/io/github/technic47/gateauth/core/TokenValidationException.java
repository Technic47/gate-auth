package io.github.technic47.gateauth.core;

import java.io.Serial;

/**
 * A token was rejected. The {@link Reason} is meant for logs only; clients get a plain 401 (spec §10), so the
 * response doesn't help anyone probe which check failed.
 */
public class TokenValidationException extends Exception {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Why a token was rejected, in the order of the checks in spec §4.3. */
    public enum Reason {
        /** Not three base64url parts, bad JSON, too long, or an unsupported {@code crit} header. */
        MALFORMED,
        /** {@code alg} is not {@code EdDSA} (this includes {@code none}). */
        UNSUPPORTED_ALGORITHM,
        /** {@code typ} doesn't match the place the token was used (assertion vs handoff). */
        WRONG_TYPE,
        /** No {@code kid}, or a {@code kid} that isn't among the configured keys. */
        UNKNOWN_KEY,
        /** The signature doesn't verify with the key named by {@code kid}. */
        BAD_SIGNATURE,
        /** Claim {@code v} is not 1. */
        UNSUPPORTED_VERSION,
        /** Claim {@code iss} differs from the configured issuer. */
        WRONG_ISSUER,
        /** Claim {@code aud} is another app. */
        WRONG_AUDIENCE,
        /** {@code exp} is in the past (beyond the allowed clock skew). */
        EXPIRED,
        /** {@code iat} is in the future (beyond the allowed clock skew). */
        NOT_YET_VALID,
        /** {@code exp - iat} is not positive or longer than {@link TokenVerifier#MAX_LIFETIME_SECONDS}. */
        LIFETIME_TOO_LONG,
        /** Handoff token's {@code nonce} doesn't match the one the app stored. */
        NONCE_MISMATCH,
        /** Handoff token was already used ({@code jti} seen before). */
        REPLAYED,
        /** A required claim is missing or has the wrong type. */
        INVALID_CLAIMS
    }

    /** Which check failed. */
    private final Reason reason;

    /**
     * Creates the exception.
     *
     * @param reason  which check failed
     * @param message detail for the log
     */
    public TokenValidationException(Reason reason, String message) {
        super(reason + ": " + message);
        this.reason = reason;
    }

    /**
     * Which check failed.
     *
     * @return the reason
     */
    public Reason reason() {
        return reason;
    }
}
