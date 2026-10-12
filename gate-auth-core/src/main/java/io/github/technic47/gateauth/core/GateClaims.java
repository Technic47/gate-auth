package io.github.technic47.gateauth.core;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Claims of a Gate Auth v1 token (spec §4.2). {@code nonce} and {@code authTime} are set only on handoff tokens.
 *
 * @param version           claim {@code v}; always {@value #VERSION}
 * @param issuer            claim {@code iss}
 * @param subject           claim {@code sub}: the gate user id, stable across renames
 * @param preferredUsername claim {@code preferred_username}: current username, for display only
 * @param audience          claim {@code aud}: the single app-name the token is for
 * @param gateRole          claim {@code gate_role}: {@code ADMIN} or {@code USER}
 * @param roles             claim {@code roles}: roles inside the app
 * @param services          claim {@code svc}: app-names the user may open
 * @param issuedAt          claim {@code iat}, epoch seconds
 * @param expiresAt         claim {@code exp}, epoch seconds
 * @param tokenId           claim {@code jti}
 * @param sessionId         claim {@code sid}: hash of the gate session id, or {@code null}
 * @param nonce             claim {@code nonce} (handoff only), or {@code null}
 * @param authTime          claim {@code auth_time} (handoff only): last password login, epoch seconds, or {@code null}
 * @param roleVersion       claim {@code rv}: role catalog version at issue time (spec §4.5), or {@code null} from
 *                          gates before 0.3.0
 */
public record GateClaims(
        int version,
        String issuer,
        String subject,
        String preferredUsername,
        String audience,
        String gateRole,
        List<String> roles,
        List<String> services,
        long issuedAt,
        long expiresAt,
        String tokenId,
        String sessionId,
        String nonce,
        Long authTime,
        Long roleVersion) {

    /** The only standard version this library knows. */
    public static final int VERSION = 1;

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * Normalizes {@code roles} and {@code services} to immutable lists ({@code null} becomes empty).
     */
    public GateClaims {
        roles = roles == null ? List.of() : List.copyOf(roles);
        services = services == null ? List.of() : List.copyOf(services);
    }

    /**
     * Claims without a role catalog version, as issued by gates before 0.3.0 (library 0.1.0 signature, kept for
     * code that builds claims directly).
     *
     * @param version           {@code v}
     * @param issuer            {@code iss}
     * @param subject           {@code sub}
     * @param preferredUsername {@code preferred_username}
     * @param audience          {@code aud}
     * @param gateRole          {@code gate_role}
     * @param roles             {@code roles}
     * @param services          {@code svc}
     * @param issuedAt          {@code iat}
     * @param expiresAt         {@code exp}
     * @param tokenId           {@code jti}
     * @param sessionId         {@code sid}
     * @param nonce             {@code nonce}
     * @param authTime          {@code auth_time}
     */
    public GateClaims(int version, String issuer, String subject, String preferredUsername, String audience,
                      String gateRole, List<String> roles, List<String> services, long issuedAt, long expiresAt,
                      String tokenId, String sessionId, String nonce, Long authTime) {
        this(version, issuer, subject, preferredUsername, audience, gateRole, roles, services, issuedAt, expiresAt,
                tokenId, sessionId, nonce, authTime, null);
    }

    /**
     * Converts to the JSON claim names of the spec; optional claims are omitted when {@code null}.
     *
     * @return claims map, ready for {@link Json#write(Object)}
     */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", version);
        m.put("iss", issuer);
        m.put("sub", subject);
        m.put("preferred_username", preferredUsername);
        m.put("aud", audience);
        m.put("gate_role", gateRole);
        m.put("roles", roles);
        m.put("svc", services);
        m.put("iat", issuedAt);
        m.put("exp", expiresAt);
        m.put("jti", tokenId);
        if (sessionId != null) {
            m.put("sid", sessionId);
        }
        if (nonce != null) {
            m.put("nonce", nonce);
        }
        if (authTime != null) {
            m.put("auth_time", authTime);
        }
        if (roleVersion != null) {
            m.put("rv", roleVersion);
        }
        return m;
    }

    /**
     * Reads claims with strict types. Unknown claims are ignored (spec §12). This does not validate the token;
     * use {@link TokenVerifier} for that.
     *
     * @param m parsed token payload
     * @return the claims
     * @throws IllegalArgumentException if a required claim is missing or has the wrong type
     */
    public static GateClaims fromMap(Map<String, Object> m) {
        return new GateClaims(
                (int) requireLong(m, "v"),
                requireString(m, "iss"),
                requireString(m, "sub"),
                optString(m, "preferred_username"),
                requireString(m, "aud"),
                optString(m, "gate_role"),
                stringList(m, "roles"),
                stringList(m, "svc"),
                requireLong(m, "iat"),
                requireLong(m, "exp"),
                optString(m, "jti"),
                optString(m, "sid"),
                optString(m, "nonce"),
                m.get("auth_time") == null ? null : requireLong(m, "auth_time"),
                m.get("rv") == null ? null : requireLong(m, "rv"));
    }

    /**
     * Starts building claims (used by the gate and in tests).
     *
     * @return a new builder with issuer {@code gate} and gate role {@code USER}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Generates 128 random bits as base64url, for {@code jti} values and similar ids.
     *
     * @return 22-character random id
     */
    public static String randomId() {
        byte[] bytes = new byte[16];
        RANDOM.nextBytes(bytes);
        return Base64Url.encode(bytes);
    }

    private static long requireLong(Map<String, Object> m, String name) {
        if (m.get(name) instanceof Long l) {
            return l;
        }
        throw new IllegalArgumentException("claim '" + name + "' missing or not an integer");
    }

    private static String requireString(Map<String, Object> m, String name) {
        String s = optString(m, name);
        if (s == null || s.isEmpty()) {
            throw new IllegalArgumentException("claim '" + name + "' missing");
        }
        return s;
    }

    private static String optString(Map<String, Object> m, String name) {
        Object v = m.get(name);
        if (v == null) {
            return null;
        }
        if (v instanceof String s) {
            return s;
        }
        throw new IllegalArgumentException("claim '" + name + "' is not a string");
    }

    private static List<String> stringList(Map<String, Object> m, String name) {
        Object v = m.get(name);
        if (v == null) {
            return List.of();
        }
        if (!(v instanceof List<?> list)) {
            throw new IllegalArgumentException("claim '" + name + "' is not an array");
        }
        List<String> out = new ArrayList<>(list.size());
        for (Object o : list) {
            if (!(o instanceof String s)) {
                throw new IllegalArgumentException("claim '" + name + "' contains a non-string");
            }
            out.add(s);
        }
        return out;
    }

    /**
     * Builder used by the gate and in tests. {@link #build(TokenType)} fills {@code v}, {@code iat} (now, unless
     * set), {@code exp} and a random {@code jti}. All setters return the builder.
     */
    public static final class Builder {
        private String issuer = "gate";
        private String subject;
        private String preferredUsername;
        private String audience;
        private String gateRole = "USER";
        private List<String> roles = List.of();
        private List<String> services = List.of();
        private Instant issuedAt;
        private Integer lifetimeSeconds;
        private String sessionId;
        private String nonce;
        private Long authTime;
        private Long roleVersion;

        Builder() {
        }

        /**
         * Sets claim {@code iss} (default {@code gate}).
         *
         * @param v the value
         * @return this builder
         */
        public Builder issuer(String v) { this.issuer = v; return this; }

        /**
         * Sets claim {@code sub}, the gate user id (required).
         *
         * @param v the value
         * @return this builder
         */
        public Builder subject(String v) { this.subject = v; return this; }

        /**
         * Sets claim {@code preferred_username}.
         *
         * @param v the value
         * @return this builder
         */
        public Builder preferredUsername(String v) { this.preferredUsername = v; return this; }

        /**
         * Sets claim {@code aud}, the app-name (required).
         *
         * @param v the value
         * @return this builder
         */
        public Builder audience(String v) { this.audience = v; return this; }

        /**
         * Sets claim {@code gate_role} (default {@code USER}).
         *
         * @param v the value
         * @return this builder
         */
        public Builder gateRole(String v) { this.gateRole = v; return this; }

        /**
         * Sets claim {@code roles}, roles inside the app.
         *
         * @param v the value
         * @return this builder
         */
        public Builder roles(List<String> v) { this.roles = v; return this; }

        /**
         * Sets claim {@code svc}, app-names the user may open.
         *
         * @param v the value
         * @return this builder
         */
        public Builder services(List<String> v) { this.services = v; return this; }

        /**
         * Sets issue time (default: now).
         *
         * @param v the value
         * @return this builder
         */
        public Builder issuedAt(Instant v) { this.issuedAt = v; return this; }

        /**
         * Sets lifetime in seconds (default: the token type's default).
         *
         * @param v the value
         * @return this builder
         */
        public Builder lifetimeSeconds(int v) { this.lifetimeSeconds = v; return this; }

        /**
         * Sets claim {@code sid}, hash of the gate session id.
         *
         * @param v the value
         * @return this builder
         */
        public Builder sessionId(String v) { this.sessionId = v; return this; }

        /**
         * Sets claim {@code nonce} (required for handoff, ignored for assertions).
         *
         * @param v the value
         * @return this builder
         */
        public Builder nonce(String v) { this.nonce = v; return this; }

        /**
         * Sets claim {@code auth_time} (handoff only).
         *
         * @param v the value
         * @return this builder
         */
        public Builder authTime(Instant v) { this.authTime = v == null ? null : v.getEpochSecond(); return this; }

        /**
         * Sets claim {@code rv}: the role catalog version at issue time (spec §4.5).
         *
         * @param v the version, or {@code null} to leave the claim out
         * @return this builder
         */
        public Builder roleVersion(Long v) { this.roleVersion = v; return this; }

        /**
         * Builds claims for the given token type. {@code nonce} and {@code auth_time} are kept only for handoff tokens.
         *
         * @param type token type; decides the default lifetime (60 s / 120 s)
         * @return the claims
         * @throws NullPointerException     if subject or audience is missing
         * @throws IllegalArgumentException if a handoff token has no nonce
         */
        public GateClaims build(TokenType type) {
            Objects.requireNonNull(subject, "subject");
            Objects.requireNonNull(audience, "audience");
            if (type == TokenType.HANDOFF && nonce == null) {
                throw new IllegalArgumentException("handoff token needs a nonce");
            }
            if (type == TokenType.ROLES) {
                throw new IllegalArgumentException("a role catalog is a RoleCatalog, not GateClaims");
            }
            long iat = (issuedAt == null ? Instant.now() : issuedAt).getEpochSecond();
            int life = lifetimeSeconds == null ? type.defaultLifetimeSeconds() : lifetimeSeconds;
            return new GateClaims(VERSION, issuer, subject, preferredUsername, audience, gateRole, roles, services,
                    iat, iat + life, randomId(), sessionId, type == TokenType.HANDOFF ? nonce : null,
                    type == TokenType.HANDOFF ? authTime : null, roleVersion);
        }
    }
}
