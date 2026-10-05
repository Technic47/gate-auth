package io.github.technic47.gateauth.core;

import java.io.Serial;
import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * The authenticated user, the same shape whichever mode logged them in (spec §8).
 *
 * @param subject  stable user id: gate {@code sub}, or {@code local:<name>} for unlinked local users.
 *                 Apps key their user data on this, never on {@code username}.
 * @param username display name (gate {@code preferred_username} or local account name); may change
 * @param gateRole global gate role ({@code ADMIN} / {@code USER}); {@code LOCAL} for local accounts
 * @param roles    roles inside this app
 * @param services app-names the user may open (informational)
 * @param mode     how this request was authenticated
 */
public record GateUser(String subject, String username, String gateRole, List<String> roles, List<String> services,
                       AuthMode mode) implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Normalizes the lists to immutable copies and defaults {@code username} to {@code subject}.
     *
     * @throws NullPointerException if {@code subject} or {@code mode} is {@code null}
     */
    public GateUser {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(mode, "mode");
        roles = roles == null ? List.of() : List.copyOf(roles);
        services = services == null ? List.of() : List.copyOf(services);
        username = username == null ? subject : username;
    }

    /**
     * Builds the user from verified token claims.
     *
     * @param claims verified claims
     * @param mode   how the request was authenticated
     * @return the user
     */
    public static GateUser from(GateClaims claims, AuthMode mode) {
        return new GateUser(claims.subject(), claims.preferredUsername(), claims.gateRole(), claims.roles(),
                claims.services(), mode);
    }

    /**
     * Whether the user is a gate administrator ({@code gate_role=ADMIN}).
     *
     * @return {@code true} for gate admins
     */
    public boolean isGateAdmin() {
        return "ADMIN".equals(gateRole);
    }

    /**
     * Whether the user has a role inside this app (exact, case-sensitive match against {@code roles}).
     *
     * @param role app role, e.g. {@code admin}
     * @return {@code true} if present
     */
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
