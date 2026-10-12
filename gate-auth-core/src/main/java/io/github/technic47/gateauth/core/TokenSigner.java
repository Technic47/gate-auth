package io.github.technic47.gateauth.core;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Signs Gate Auth tokens (JWS compact serialization, {@code alg=EdDSA}). Used by GateService only.
 * Thread-safe.
 */
public final class TokenSigner {

    private final GateSigningKey key;

    /**
     * Creates a signer.
     *
     * @param key the gate's signing key
     */
    public TokenSigner(GateSigningKey key) {
        this.key = key;
    }

    /**
     * The id of the signing key, written to every token header.
     *
     * @return the {@code kid}
     */
    public String kid() {
        return key.kid();
    }

    /**
     * Signs claims as a token of the given type.
     *
     * @param type   assertion or handoff; sets the {@code typ} header
     * @param claims the claims, usually from {@link GateClaims#builder()}
     * @return the token, {@code header.payload.signature}
     * @throws IllegalArgumentException if the lifetime exceeds {@link TokenVerifier#MAX_LIFETIME_SECONDS}
     *                                  or a handoff token has no nonce
     */
    public String sign(TokenType type, GateClaims claims) {
        if (type == TokenType.ROLES) {
            throw new IllegalArgumentException("sign role catalogs with signRoleCatalog");
        }
        if (claims.expiresAt() - claims.issuedAt() > TokenVerifier.MAX_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("token lifetime exceeds " + TokenVerifier.MAX_LIFETIME_SECONDS + " s");
        }
        if (type == TokenType.HANDOFF && claims.nonce() == null) {
            throw new IllegalArgumentException("handoff token needs a nonce");
        }
        return signPayload(type, claims.toMap());
    }

    /**
     * Signs a role catalog (spec §4.5), served by the gate at {@code /.well-known/gate/apps/{app}/roles}.
     *
     * @param catalog the catalog, usually from {@link RoleCatalog#issue}
     * @return the token, {@code header.payload.signature}, header {@code typ: gate-roles+jwt}
     * @throws IllegalArgumentException if the lifetime exceeds {@link RoleCatalog#MAX_LIFETIME_SECONDS}
     */
    public String signRoleCatalog(RoleCatalog catalog) {
        long lifetime = catalog.expiresAt() - catalog.issuedAt();
        if (lifetime <= 0 || lifetime > RoleCatalog.MAX_LIFETIME_SECONDS) {
            throw new IllegalArgumentException("role catalog lifetime must be 1 s to " + RoleCatalog.MAX_LIFETIME_SECONDS + " s");
        }
        return signPayload(TokenType.ROLES, catalog.toMap());
    }

    private String signPayload(TokenType type, Map<String, Object> payload) {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "EdDSA");
        header.put("kid", key.kid());
        header.put("typ", type.typ());
        String signingInput = Base64Url.encode(Json.write(header)) + "." + Base64Url.encode(Json.write(payload));
        try {
            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(key.privateKey());
            sig.update(signingInput.getBytes(StandardCharsets.US_ASCII));
            return signingInput + "." + Base64Url.encode(sig.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Signing failed", e);
        }
    }
}
