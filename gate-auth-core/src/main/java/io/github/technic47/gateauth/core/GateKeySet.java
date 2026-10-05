package io.github.technic47.gateauth.core;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The gate's public verification keys, by {@code kid}. Usually one key; two during a key rotation (spec §3).
 * Immutable.
 */
public final class GateKeySet {

    private final Map<String, PublicKey> keys;

    private GateKeySet(Map<String, PublicKey> keys) {
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Key set is empty");
        }
        this.keys = Collections.unmodifiableMap(keys);
    }

    /**
     * Builds a key set; each key's {@code kid} is computed from the key.
     *
     * @param keys one or more Ed25519 public keys
     * @return the key set
     * @throws IllegalArgumentException if no keys are given
     */
    public static GateKeySet of(PublicKey... keys) {
        Map<String, PublicKey> map = new LinkedHashMap<>();
        for (PublicKey key : keys) {
            map.put(Ed25519Keys.kid(key), key);
        }
        return new GateKeySet(map);
    }

    /**
     * Parses keys from text: one or more {@code -----BEGIN PUBLIC KEY-----} PEM blocks, a single JWK object, or a
     * JWKS ({@code {"keys":[…]}}). The {@code kid} is always computed from the key; a JWK's own {@code kid} must
     * match it, so a typo can't silently attach the wrong id.
     *
     * @param text PEM, JWK or JWKS text
     * @return the key set
     * @throws IllegalArgumentException if no valid Ed25519 key is found or a JWK {@code kid} doesn't match
     */
    @SuppressWarnings("unchecked")
    public static GateKeySet parse(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("No public keys given");
        }
        String trimmed = text.trim();
        List<PublicKey> found = new ArrayList<>();
        if (trimmed.startsWith("{")) {
            Map<String, Object> obj = Json.parseObject(trimmed);
            List<Object> list = obj.containsKey("keys") ? (List<Object>) obj.get("keys") : List.of(obj);
            for (Object o : list) {
                Map<String, Object> jwk = (Map<String, Object>) o;
                PublicKey key = Ed25519Keys.publicFromJwk(jwk);
                Object kid = jwk.get("kid");
                if (kid != null && !Ed25519Keys.kid(key).equals(kid)) {
                    throw new IllegalArgumentException("JWK kid '" + kid + "' does not match the key thumbprint "
                            + Ed25519Keys.kid(key));
                }
                found.add(key);
            }
        } else {
            String marker = "-----END PUBLIC KEY-----";
            int from = 0;
            while (true) {
                int end = trimmed.indexOf(marker, from);
                if (end < 0) {
                    break;
                }
                found.add(Ed25519Keys.publicFromPem(trimmed.substring(from, end + marker.length())));
                from = end + marker.length();
            }
            if (found.isEmpty()) {
                throw new IllegalArgumentException("No PEM public key found");
            }
        }
        return of(found.toArray(PublicKey[]::new));
    }

    /**
     * Looks up a key by id.
     *
     * @param kid key id from a token header
     * @return the key, or empty if this set doesn't contain it
     */
    public Optional<PublicKey> find(String kid) {
        return Optional.ofNullable(keys.get(kid));
    }

    /**
     * All keys by {@code kid}.
     *
     * @return unmodifiable map
     */
    public Map<String, PublicKey> asMap() {
        return keys;
    }

    /**
     * Writes the set as a JWKS document, as served at {@code /.well-known/jwks.json}.
     *
     * @return JWKS JSON; contains public keys only
     */
    public String toJwks() {
        List<Object> list = new ArrayList<>();
        keys.values().forEach(k -> list.add(Ed25519Keys.toPublicJwk(k)));
        return Json.write(Map.of("keys", list));
    }
}
