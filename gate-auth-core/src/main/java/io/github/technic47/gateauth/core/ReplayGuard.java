package io.github.technic47.gateauth.core;

import java.time.Clock;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Remembers token ids until they expire, so a handoff token can be used only once (spec §6.4).
 *
 * <p>In memory, which is enough for one app instance. Several instances of one app would need a shared store.
 */
public final class ReplayGuard {

    private static final int MAX_ENTRIES = 100_000;

    private final Map<String, Long> seen = new ConcurrentHashMap<>();
    private final Clock clock;

    /**
     * Creates a guard with a custom clock (for tests).
     *
     * @param clock source of the current time
     */
    public ReplayGuard(Clock clock) {
        this.clock = clock;
    }

    /** Creates a guard using the system UTC clock. */
    public ReplayGuard() {
        this(Clock.systemUTC());
    }

    /**
     * Records a token id and tells whether this is its first use.
     *
     * @param tokenId              the token's {@code jti}
     * @param expiresAtEpochSecond the token's {@code exp}; the id is forgotten some time after it
     * @return {@code true} the first time this id is used; {@code false} if it was seen before
     * @throws IllegalStateException if an implausible number of unexpired ids is stored (flood protection)
     */
    public boolean firstUse(String tokenId, long expiresAtEpochSecond) {
        purgeIfNeeded();
        return seen.putIfAbsent(tokenId, expiresAtEpochSecond + 60) == null;
    }

    private void purgeIfNeeded() {
        long now = clock.instant().getEpochSecond();
        if (seen.size() > MAX_ENTRIES / 10) {
            seen.values().removeIf(exp -> exp < now);
        }
        if (seen.size() > MAX_ENTRIES) {
            // Tokens are signed, so this only happens with a misbehaving gate.
            throw new IllegalStateException("Too many unexpired handoff tokens");
        }
    }
}
