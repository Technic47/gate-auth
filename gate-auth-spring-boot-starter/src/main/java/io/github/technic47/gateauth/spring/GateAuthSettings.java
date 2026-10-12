package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import io.github.technic47.gateauth.core.GateKeySet;
import io.github.technic47.gateauth.spring.GateAuthProperties.LocalUser;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.server.PathContainer;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Validated, derived view of {@link GateAuthProperties}. Construction fails fast on bad config (spec §11), so a
 * misconfigured app doesn't start instead of starting unprotected. Available as a bean; most methods are internal
 * to the starter.
 */
public final class GateAuthSettings {

    private static final Logger log = LoggerFactory.getLogger(GateAuthSettings.class);
    private static final Pattern APP_NAME = Pattern.compile("[a-z0-9][a-z0-9._-]{0,63}");

    private final GateAuthProperties props;
    private final String cookiePrefix;
    private final List<String> publicOrigins;
    private final List<PathPattern> apiPatterns;
    private final GateKeySet keys;
    private final String gateUrl;
    private final String rolesGateUrl;
    private final List<IpAddressMatcher> localNetworks;

    /**
     * Validates the properties and derives cookie names, origins, keys and networks.
     *
     * @param props bound {@code gate.auth.*} properties
     * @throws IllegalStateException listing every configuration problem found
     */
    public GateAuthSettings(GateAuthProperties props) {
        this.props = props;
        List<String> errors = new ArrayList<>();

        boolean edge = props.edge().enabled();
        boolean direct = props.direct().enabled();
        boolean local = props.local().enabled();

        if (props.appName() == null || !APP_NAME.matcher(props.appName()).matches()) {
            errors.add("gate.auth.app-name is required: lowercase letters, digits, '.', '_', '-' (got '"
                    + props.appName() + "')");
        }
        if (!edge && !direct && !local) {
            errors.add("no mode enabled: set at least one of gate.auth.edge.enabled, gate.auth.direct.enabled, "
                    + "gate.auth.local.enabled");
        }
        if (props.basePath() == null || !props.basePath().matches("/[A-Za-z0-9/_-]*[A-Za-z0-9_-]")) {
            errors.add("gate.auth.base-path must look like /auth");
        }

        this.publicOrigins = new ArrayList<>();
        for (String url : nullSafe(props.publicUrls())) {
            try {
                publicOrigins.add(origin(URI.create(url.trim())));
            } catch (IllegalArgumentException e) {
                errors.add("gate.auth.public-urls: not a URL: " + url);
            }
        }
        if (publicOrigins.isEmpty()) {
            errors.add("gate.auth.public-urls is required (every origin the app is reached under)");
        }

        this.apiPatterns = new ArrayList<>();
        for (String p : nullSafe(props.apiPaths())) {
            apiPatterns.add(PathPatternParser.defaultInstance.parse(p));
        }

        boolean roles = props.roles() != null && props.roles().enabled();
        GateKeySet parsedKeys = null;
        if (edge || direct || roles) {
            try {
                parsedKeys = GateKeySet.parse(readKeys(props));
            } catch (RuntimeException | IOException e) {
                errors.add("gate.auth.public-keys / public-keys-location: " + e.getMessage());
            }
        }
        this.keys = parsedKeys;

        String gate = null;
        if (direct) {
            gate = props.direct().gateUrl();
            if (gate == null || !gate.startsWith("https://") && props.cookieSecure()) {
                errors.add("gate.auth.direct.gate-url is required and must be https:// (e.g. https://144.31.187.7)");
            } else {
                gate = gate.replaceAll("/+$", "");
            }
            if (props.localSecret() == null || props.localSecret().length() < 32) {
                errors.add("gate.auth.local-secret is required for direct mode (≥ 32 characters, random)");
            }
        }
        this.gateUrl = gate;

        String rolesGate = null;
        if (roles) {
            rolesGate = props.roles().gateUrl() != null && !props.roles().gateUrl().isBlank()
                    ? props.roles().gateUrl() : props.direct().gateUrl();
            if (rolesGate == null || !rolesGate.startsWith("https://") && props.cookieSecure()) {
                errors.add("gate.auth.roles.enabled needs the gate's https:// URL in gate.auth.roles.gate-url "
                        + "or gate.auth.direct.gate-url");
            } else {
                rolesGate = rolesGate.replaceAll("/+$", "");
            }
            if (props.roles().refresh() == null || props.roles().refresh().toSeconds() < 60) {
                errors.add("gate.auth.roles.refresh must be at least 1m");
            }
        }
        this.rolesGateUrl = rolesGate;

        this.localNetworks = new ArrayList<>();
        if (local) {
            List<String> nets = nullSafe(props.local().allowedNetworks());
            if (nets.isEmpty()) {
                errors.add("gate.auth.local.allowed-networks is required when local mode is enabled");
            }
            for (String n : nets) {
                try {
                    localNetworks.add(new IpAddressMatcher(n.trim()));
                } catch (IllegalArgumentException e) {
                    errors.add("gate.auth.local.allowed-networks: bad CIDR " + n);
                }
            }
            List<LocalUser> users = nullSafe(props.local().users());
            if (users.isEmpty()) {
                errors.add("gate.auth.local.users is required when local mode is enabled");
            }
            for (LocalUser u : users) {
                if (u.name() == null || u.name().isBlank()) {
                    errors.add("gate.auth.local.users: name is required");
                }
                String h = stripBcryptPrefix(u.hash());
                if (h == null || !h.matches("\\$2[aby]?\\$\\d\\d\\$.{53}")) {
                    errors.add("gate.auth.local.users[" + u.name() + "]: hash must be a bcrypt hash");
                }
            }
        }

        if (!errors.isEmpty()) {
            throw new IllegalStateException("Invalid gate-auth configuration:\n - " + String.join("\n - ", errors));
        }

        this.cookiePrefix = props.appName().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_");

        log.info("gate-auth: app={} modes: edge={} direct={} local={} origins={}",
                props.appName(), edge, direct, local, publicOrigins);
        if (local) {
            log.warn("gate-auth: LOCAL (break-glass) login is ENABLED for networks {}. Disable it when the gate "
                    + "is reachable again (gate.auth.local.enabled=false).", props.local().allowedNetworks());
        }
        if (!props.cookieSecure()) {
            log.warn("gate-auth: cookie-secure=false. Only for local development over plain http.");
        }
    }

    // ---------------------------------------------------------------- accessors

    /**
     * The raw properties.
     *
     * @return bound {@code gate.auth.*} properties
     */
    public GateAuthProperties props() {
        return props;
    }

    /**
     * This app's id: {@code aud}, nginx {@code X-Service-Name}, the gate's service name.
     *
     * @return the app-name
     */
    public String appName() {
        return props.appName();
    }

    /**
     * Whether edge mode ({@code X-Gate-Assertion} from VPS nginx) is on.
     *
     * @return {@code true} if enabled
     */
    public boolean edgeEnabled() {
        return props.edge().enabled();
    }

    /**
     * Whether direct mode (LAN login through the gate) is on.
     *
     * @return {@code true} if enabled
     */
    public boolean directEnabled() {
        return props.direct().enabled();
    }

    /**
     * Whether local (break-glass) login is on.
     *
     * @return {@code true} if enabled
     */
    public boolean localEnabled() {
        return props.local().enabled();
    }

    GateKeySet keys() {
        return keys;
    }

    /**
     * Where the role catalog is fetched from (spec §4.5), without trailing slash; set only when
     * {@code gate.auth.roles.enabled}.
     *
     * @return the gate URL or {@code null}
     */
    public String rolesGateUrl() {
        return rolesGateUrl;
    }

    /**
     * Whether the role catalog is synced from the gate.
     *
     * @return {@code gate.auth.roles.enabled}
     */
    public boolean rolesEnabled() {
        return rolesGateUrl != null;
    }

    /**
     * The gate's public URL without trailing slash; set only in direct mode.
     *
     * @return e.g. {@code https://144.31.187.7}, or {@code null}
     */
    public String gateUrl() {
        return gateUrl;
    }

    /**
     * Where the library's endpoints live.
     *
     * @return e.g. {@code /auth}
     */
    public String basePath() {
        return props.basePath();
    }

    String callbackPath() {
        return props.basePath() + "/callback";
    }

    /**
     * Name of the app session cookie (direct and local modes).
     *
     * @return e.g. {@code BIKESERVICE_SESSION}
     */
    public String sessionCookieName() {
        return cookiePrefix + "_SESSION";
    }

    String handoffCookieName() {
        return cookiePrefix + "_HANDOFF";
    }

    /**
     * Name of the CSRF cookie an SPA reads and echoes as {@code X-XSRF-TOKEN}.
     *
     * @return e.g. {@code BIKESERVICE_XSRF}
     */
    public String csrfCookieName() {
        return cookiePrefix + "_XSRF";
    }

    boolean cookieSecure() {
        return props.cookieSecure();
    }

    Duration sessionTtl(AuthMode mode) {
        return mode == AuthMode.LOCAL ? props.local().sessionTtl() : props.direct().sessionTtl();
    }

    List<String> adminImpliesRoles() {
        return nullSafe(props.adminImpliesRoles());
    }

    // ---------------------------------------------------------------- request helpers

    /** Path inside the app (without context path). */
    static String path(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String ctx = request.getContextPath();
        return ctx != null && !ctx.isEmpty() && uri.startsWith(ctx) ? uri.substring(ctx.length()) : uri;
    }

    boolean isApi(HttpServletRequest request) {
        PathContainer pc = PathContainer.parsePath(path(request));
        for (PathPattern p : apiPatterns) {
            if (p.matches(pc)) {
                return true;
            }
        }
        return false;
    }

    boolean isAuthEndpoint(HttpServletRequest request) {
        String p = path(request);
        return p.equals(basePath()) || p.startsWith(basePath() + "/");
    }

    /** The configured public origin the browser used for this request, if it is one of {@code public-urls}. */
    Optional<String> requestOrigin(HttpServletRequest request) {
        String o = origin(request.getScheme(), request.getServerName(), request.getServerPort());
        return publicOrigins.contains(o) ? Optional.of(o) : Optional.empty();
    }

    boolean isAllowedOrigin(String originHeader) {
        if (originHeader == null) {
            return false;
        }
        try {
            return publicOrigins.contains(origin(URI.create(originHeader.trim())));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    boolean isLocalNetwork(String remoteAddr) {
        if (remoteAddr == null) {
            return false;
        }
        for (IpAddressMatcher m : localNetworks) {
            try {
                if (m.matches(remoteAddr)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // address family mismatch etc.
            }
        }
        return false;
    }

    /** Safe post-login target: a relative path inside this app, else "/". */
    static String safeReturnPath(String candidate) {
        if (candidate == null || candidate.isEmpty() || candidate.length() > 2048) {
            return "/";
        }
        if (!candidate.startsWith("/") || candidate.startsWith("//") || candidate.startsWith("/\\")) {
            return "/";
        }
        for (int i = 0; i < candidate.length(); i++) {
            char c = candidate.charAt(i);
            if (c < 0x21 || c == 0x7f || c == '\\') {
                return "/";
            }
        }
        return candidate;
    }

    static String stripBcryptPrefix(String hash) {
        if (hash == null) {
            return null;
        }
        return hash.startsWith("{bcrypt}") ? hash.substring("{bcrypt}".length()) : hash;
    }

    // ---------------------------------------------------------------- internals

    static String origin(URI uri) {
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException("not absolute: " + uri);
        }
        return origin(uri.getScheme(), uri.getHost(), uri.getPort());
    }

    static String origin(String scheme, String host, int port) {
        String s = scheme.toLowerCase(Locale.ROOT);
        String h = host.toLowerCase(Locale.ROOT);
        if (h.contains(":") && !h.startsWith("[")) {
            h = "[" + h + "]"; // IPv6 literal
        }
        boolean defaultPort = port < 0 || ("https".equals(s) && port == 443) || ("http".equals(s) && port == 80);
        return defaultPort ? s + "://" + h : s + "://" + h + ":" + port;
    }

    private static String readKeys(GateAuthProperties props) throws IOException {
        if (props.publicKeys() != null && !props.publicKeys().isBlank()) {
            return props.publicKeys();
        }
        if (props.publicKeysLocation() != null) {
            try (InputStream in = props.publicKeysLocation().getInputStream()) {
                return new String(in.readAllBytes(), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalArgumentException("not set (required for edge and direct modes)");
    }

    private static <T> List<T> nullSafe(List<T> list) {
        return list == null ? List.of() : list;
    }
}
