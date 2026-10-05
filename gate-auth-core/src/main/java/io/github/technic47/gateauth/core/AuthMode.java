package io.github.technic47.gateauth.core;

/** How the current user was authenticated (spec §2). */
public enum AuthMode {
    /** Through VPS nginx, signed {@code X-Gate-Assertion} on this request. */
    EDGE,
    /** LAN login via gate handoff, app-side session. */
    DIRECT,
    /** Break-glass account from app config, app-side session. */
    LOCAL
}
