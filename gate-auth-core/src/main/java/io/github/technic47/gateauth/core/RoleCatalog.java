package io.github.technic47.gateauth.core;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * The roles an app may receive, as the gate publishes them (spec §4.5, token type {@link TokenType#ROLES}).
 * The gate is the only place where roles are defined; apps sync this list and decide what each role allows.
 *
 * @param version   claim {@code v}; always {@value GateClaims#VERSION}
 * @param issuer    claim {@code iss}
 * @param audience  claim {@code aud}: the app-name the catalog is for
 * @param issuedAt  claim {@code iat}, epoch seconds
 * @param expiresAt claim {@code exp}, epoch seconds
 * @param catalogVersion claim {@code rv}: increases with every change of a role definition in the gate
 * @param roles     claim {@code roles}: the active roles for this app, global ones included, in the gate's order
 */
public record RoleCatalog(int version, String issuer, String audience, long issuedAt, long expiresAt,
                          long catalogVersion, List<Role> roles) {

    /** Lifetime the gate gives a catalog: one day. */
    public static final long DEFAULT_LIFETIME_SECONDS = TokenType.ROLES.defaultLifetimeSeconds();
    /** Upper bound for {@code exp - iat} accepted from the gate: seven days. */
    public static final long MAX_LIFETIME_SECONDS = 7 * 86_400;
    /** What a role code looks like (spec §4.4). */
    public static final Pattern CODE = Pattern.compile("^[a-z][a-z0-9_-]{0,31}$");

    /** Validates the fields and copies the list. */
    public RoleCatalog {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(audience, "audience");
        if (catalogVersion < 0) {
            throw new IllegalArgumentException("rv must not be negative");
        }
        roles = roles == null ? List.of() : List.copyOf(roles);
    }

    /**
     * A new catalog as the gate issues it: {@code v = 1}, lifetime {@link #DEFAULT_LIFETIME_SECONDS}.
     *
     * @param issuer         the gate id
     * @param audience       the app-name
     * @param catalogVersion the current role catalog version
     * @param roles          the app's active roles
     * @param now            issue time
     * @return the catalog
     */
    public static RoleCatalog issue(String issuer, String audience, long catalogVersion, List<Role> roles,
                                    Instant now) {
        long iat = now.getEpochSecond();
        return new RoleCatalog(GateClaims.VERSION, issuer, audience, iat, iat + DEFAULT_LIFETIME_SECONDS,
                catalogVersion, roles);
    }

    /**
     * The role with this code, if the catalog has it.
     *
     * @param code role code
     * @return the role or {@code null}
     */
    public Role find(String code) {
        return roles.stream().filter(r -> r.code().equals(code)).findFirst().orElse(null);
    }

    /**
     * The catalog as JWT claims.
     *
     * @return claim name → value, ready for {@link Json#write(Object)}
     */
    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("v", version);
        m.put("iss", issuer);
        m.put("aud", audience);
        m.put("iat", issuedAt);
        m.put("exp", expiresAt);
        m.put("rv", catalogVersion);
        List<Map<String, Object>> list = new ArrayList<>();
        for (Role r : roles) {
            Map<String, Object> role = new LinkedHashMap<>();
            role.put("code", r.code());
            role.put("name", r.name());
            if (r.description() != null) {
                role.put("description", r.description());
            }
            role.put("global", r.global());
            list.add(role);
        }
        m.put("roles", list);
        return m;
    }

    /**
     * Reads a catalog from parsed JWT claims.
     *
     * @param m the claims
     * @return the catalog
     * @throws IllegalArgumentException if a claim is missing or has the wrong type
     */
    public static RoleCatalog fromMap(Map<String, Object> m) {
        Object list = m.get("roles");
        if (!(list instanceof List<?> items)) {
            throw new IllegalArgumentException("claim 'roles' missing or not an array");
        }
        List<Role> roles = new ArrayList<>(items.size());
        for (Object item : items) {
            if (!(item instanceof Map<?, ?> raw)) {
                throw new IllegalArgumentException("claim 'roles' contains a non-object");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> r = (Map<String, Object>) raw;
            roles.add(new Role(string(r, "code", true), string(r, "name", true), string(r, "description", false),
                    Boolean.TRUE.equals(r.get("global"))));
        }
        return new RoleCatalog((int) number(m, "v"), string(m, "iss", true), string(m, "aud", true),
                number(m, "iat"), number(m, "exp"), number(m, "rv"), roles);
    }

    private static long number(Map<String, Object> m, String name) {
        if (m.get(name) instanceof Long l) {
            return l;
        }
        throw new IllegalArgumentException("claim '" + name + "' missing or not an integer");
    }

    private static String string(Map<String, Object> m, String name, boolean required) {
        Object v = m.get(name);
        if (v == null) {
            if (required) {
                throw new IllegalArgumentException("'" + name + "' missing");
            }
            return null;
        }
        if (!(v instanceof String s)) {
            throw new IllegalArgumentException("'" + name + "' is not a string");
        }
        return s;
    }

    /**
     * One role of the catalog.
     *
     * @param code        what tokens carry in {@code roles}, e.g. {@code editor}; never changes in the gate
     * @param name        display name, e.g. "Editor"
     * @param description what the role is for, or {@code null}
     * @param global      defined once in the gate for all apps (assigned per app all the same)
     */
    public record Role(String code, String name, String description, boolean global) {

        /** Checks the code and name. */
        public Role {
            if (code == null || !CODE.matcher(code).matches()) {
                throw new IllegalArgumentException("invalid role code: " + code);
            }
            Objects.requireNonNull(name, "name");
        }
    }
}
