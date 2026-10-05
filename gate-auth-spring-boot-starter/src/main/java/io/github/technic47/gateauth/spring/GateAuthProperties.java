package io.github.technic47.gateauth.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;
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
        @DefaultValue Local local) {

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
