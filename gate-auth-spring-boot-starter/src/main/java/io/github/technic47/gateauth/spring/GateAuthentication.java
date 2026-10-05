package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.GateUser;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Spring Security {@code Authentication} for a {@link GateUser}. App roles become {@code ROLE_<UPPERCASE>}.
 *
 * In controllers: {@code @AuthenticationPrincipal GateUser user}.
 */
public final class GateAuthentication extends AbstractAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    /** The authenticated user. */
    private final GateUser user;

    /**
     * Creates an authenticated token.
     *
     * @param user              the user
     * @param adminImpliesRoles app roles added when the user is a gate admin
     */
    public GateAuthentication(GateUser user, List<String> adminImpliesRoles) {
        super(authorities(user, adminImpliesRoles));
        this.user = user;
        super.setAuthenticated(true);
    }

    @Override
    public GateUser getPrincipal() {
        return user;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public String getName() {
        return user.subject();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (authenticated) {
            throw new IllegalArgumentException("Create a new GateAuthentication instead");
        }
        super.setAuthenticated(false);
    }

    static List<GrantedAuthority> authorities(GateUser user, List<String> adminImpliesRoles) {
        Set<String> roles = new LinkedHashSet<>(user.roles());
        if (user.isGateAdmin()) {
            roles.addAll(adminImpliesRoles);
        }
        List<GrantedAuthority> out = new ArrayList<>();
        for (String r : roles) {
            out.add(new SimpleGrantedAuthority("ROLE_" + r.toUpperCase(Locale.ROOT)));
        }
        return out;
    }
}
