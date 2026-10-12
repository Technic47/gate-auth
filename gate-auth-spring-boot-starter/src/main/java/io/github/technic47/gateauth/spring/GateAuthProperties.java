package io.github.technic47.gateauth.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.core.io.Resource;

import java.time.Duration;
import java.util.List;

/**
 * {@code gate.auth.*} configuration (spec §11). Modes are read once at startup; change them by restarting the app.
 *
 * @param appName           this app's id: equals {@code aud}, nginx {@code X-Service-Name} and the gate's service name
 * @param issuer            expected {@code iss}
 * @param publicUrls        every origin the app is reached under (VPS and LAN); used for Origin checks and the
 *                          direct-mode {@code redirect_uri}
 * @param apiPaths          path patterns answered with JSON 401 instead of a login redirect
 * @param publicKeys        gate public key(s): PEM block(s), JWK or JWKS
 * @param publicKeysLocation alternative to {@code publicKeys}: a file/classpath resource with the same content
 * @param adminImpliesRoles app roles granted when {@code gate_role=ADMIN}
 * @param localSecret       HMAC secret for the direct-mode handoff cookie (≥ 32 chars)
 * @param basePath          where the library's endpoints live ({@code /auth})
 * @param cookieSecure      {@code false} only for plain-http local development
 * @param clockSkew         allowed clock difference to the gate
 * @param edge              edge mode settings
 * @param direct            direct (LAN) mode settings
 * @param local             local (break-glass) mode settings
 * @param roles             role catalog sync from the gate (spec §4.5)
 */
@ConfigurationProperties("gate.auth")
public record GateAuthProperties(
        String appName,
        @DefaultValue("gate") String issuer,
        List<String> publicUrls,
        @DefaultValue("/api/**") List<String> apiPaths,
        String publicKeys,
        Resource publicKeysLocation,
        List<String> adminImpliesRoles,
        String localSecret,
        @DefaultValue("/auth") String basePath,
        @DefaultValue("true") boolean cookieSecure,
        @DefaultValue("30s") Duration clockSkew,
        @DefaultValue Edge edge,
        @DefaultValue Direct direct,
        @DefaultValue Local local,
        @DefaultValue Roles roles) {

    /** The constructor Spring binds {@code gate.auth.*} to (the record has a second, compatibility constructor). */
    @ConstructorBinding
    public GateAuthProperties {
    }

    /**
     * Properties without role catalog settings (library 0.1.0 signature, kept for code that builds them directly).
     *
     * @param appName            see the record
     * @param issuer             see the record
     * @param publicUrls         see the record
     * @param apiPaths           see the record
     * @param publicKeys         see the record
     * @param publicKeysLocation see the record
     * @param adminImpliesRoles  see the record
     * @param localSecret        see the record
     * @param basePath           see the record
     * @param cookieSecure       see the record
     * @param clockSkew          see the record
     * @param edge               see the record
     * @param direct             see the record
     * @param local              see the record
     */
    public GateAuthProperties(String appName, String issuer, List<String> publicUrls, List<String> apiPaths,
                              String publicKeys, Resource publicKeysLocation, List<String> adminImpliesRoles,
                              String localSecret, String basePath, boolean cookieSecure, Duration clockSkew,
                              Edge edge, Direct direct, Local local) {
        this(appName, issuer, publicUrls, apiPaths, publicKeys, publicKeysLocation, adminImpliesRoles, localSecret,
                basePath, cookieSecure, clockSkew, edge, direct, local,
                new Roles(false, null, Duration.ofMinutes(10), List.of(), true));
    }

    /**
     * Role catalog sync (spec §4.5): the gate defines the roles, the app fetches the list for itself. Authorization
     * never depends on it (it uses the token's {@code roles}); the list adds names, descriptions and change events.
     *
     * @param enabled                fetch the catalog ({@code false} by default)
     * @param gateUrl                the gate's URL; defaults to {@code direct.gate-url}
     * @param refresh                how often to fetch; a token with a newer {@code rv} triggers a fetch at once
     * @param handled                role codes this app implements; differences to the gate's list are logged
     * @param trustAnyTlsCertificate accept the gate's TLS certificate without checking it (the gate runs on a bare
     *                               IP with a self-signed certificate). Safe because the catalog itself is signed
     *                               with the gate's key and verified
     */
    public record Roles(
            @DefaultValue("false") boolean enabled,
            String gateUrl,
            @DefaultValue("10m") Duration refresh,
            List<String> handled,
            @DefaultValue("true") boolean trustAnyTlsCertificate) {
    }

    /**
     * Edge mode: requests through VPS nginx carry a signed assertion.
     *
     * @param enabled accept {@code X-Gate-Assertion} from VPS nginx
     * @param header  header name
     */
    public record Edge(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("X-Gate-Assertion") String header) {
    }

    /**
     * Direct mode: LAN login through a gate handoff, then an app-side session.
     *
     * @param enabled      LAN login through a gate handoff
     * @param gateUrl      the gate's public URL, e.g. {@code https://144.31.187.7}
     * @param sessionTtl   absolute lifetime of a direct-mode session
     * @param recheckAfter silent re-check with the gate after this long
     * @param recheckRetry wait this long before trying a failed/unanswered re-check again
     */
    public record Direct(
            @DefaultValue("false") boolean enabled,
            String gateUrl,
            @DefaultValue("30d") Duration sessionTtl,
            @DefaultValue("24h") Duration recheckAfter,
            @DefaultValue("1h") Duration recheckRetry) {
    }

    /**
     * Local mode: break-glass accounts for when the gate is unreachable.
     *
     * @param enabled         break-glass accounts
     * @param allowedNetworks CIDRs local login is allowed from (required)
     * @param users           accounts
     * @param sessionTtl      absolute lifetime of a local session
     * @param maxFailures     failed attempts before lockout (per user and per IP)
     * @param lockout         lockout duration
     */
    public record Local(
            @DefaultValue("false") boolean enabled,
            List<String> allowedNetworks,
            List<LocalUser> users,
            @DefaultValue("12h") Duration sessionTtl,
            @DefaultValue("5") int maxFailures,
            @DefaultValue("15m") Duration lockout) {
    }

    /**
     * One break-glass account. {@link #toString()} omits the hash.
     *
     * @param name   login name
     * @param hash   bcrypt hash ({@code $2a$…}, optional {@code {bcrypt}} prefix)
     * @param roles  app roles
     * @param linkTo gate {@code sub} this account acts as (so it sees the owner's data); empty = {@code local:<name>}
     */
    public record LocalUser(String name, String hash, List<String> roles, String linkTo) {

        @Override
        public String toString() {
            return "LocalUser[name=" + name + ", roles=" + roles + ", linkTo=" + linkTo + "]"; // no hash
        }
    }
}
