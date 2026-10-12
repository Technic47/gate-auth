package io.github.technic47.gateauth.core;

/**
 * The Gate Auth v1 token types (spec §4.1, §4.5). The JOSE {@code typ} header keeps them apart, so a token issued
 * for one purpose is never accepted for another.
 */
public enum TokenType {

    /** Edge mode: sent on every request through VPS nginx as {@code X-Gate-Assertion}. Lives 60 s. */
    ASSERTION("gate-assertion+jwt", 60),

    /** Direct mode: posted by the browser to the app's callback to finish a LAN login. Lives 120 s. */
    HANDOFF("gate-handoff+jwt", 120),

    /**
     * Role catalog: the roles an app may receive, served by the gate at
     * {@code /.well-known/gate/apps/{app}/roles} (spec §4.5). Lives one day. Signed with
     * {@link TokenSigner#signRoleCatalog(RoleCatalog)}, verified with {@link TokenVerifier#verifyRoleCatalog(String)}.
     */
    ROLES("gate-roles+jwt", 86_400);

    private final String typ;
    private final int defaultLifetimeSeconds;

    TokenType(String typ, int defaultLifetimeSeconds) {
        this.typ = typ;
        this.defaultLifetimeSeconds = defaultLifetimeSeconds;
    }

    /**
     * The JOSE {@code typ} header value.
     *
     * @return e.g. {@code gate-assertion+jwt}
     */
    public String typ() {
        return typ;
    }

    /**
     * Lifetime the gate uses unless told otherwise.
     *
     * @return seconds between {@code iat} and {@code exp}
     */
    public int defaultLifetimeSeconds() {
        return defaultLifetimeSeconds;
    }
}
