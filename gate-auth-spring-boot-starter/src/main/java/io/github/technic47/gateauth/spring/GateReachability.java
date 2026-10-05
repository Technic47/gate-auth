package io.github.technic47.gateauth.spring;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.time.Clock;

/**
 * Whether the gate is probably reachable, so a silent re-check doesn't strand the user on a browser
 * "connection failed" page while the VPS or the internet is down (spec §6.6).
 *
 * Replace the bean to change the check.
 */
public interface GateReachability {

    /**
     * Whether a silent re-check redirect to the gate is likely to work.
     *
     * @return {@code true} if the gate looks reachable
     */
    boolean isReachable();

    /** TCP connect to the gate's host:port, result cached for a minute. */
    final class Tcp implements GateReachability {

        private static final long CACHE_SECONDS = 60;
        private static final int TIMEOUT_MILLIS = 1500;

        private final String host;
        private final int port;
        private final Clock clock;
        private volatile long checkedAt = Long.MIN_VALUE;
        private volatile boolean reachable;

        /**
         * Creates the check.
         *
         * @param gateUrl the gate's public URL; host and port are taken from it
         * @param clock   source of the current time (for the cache)
         */
        public Tcp(String gateUrl, Clock clock) {
            URI uri = URI.create(gateUrl);
            this.host = uri.getHost();
            this.port = uri.getPort() > 0 ? uri.getPort() : ("http".equals(uri.getScheme()) ? 80 : 443);
            this.clock = clock;
        }

        @Override
        public boolean isReachable() {
            long now = clock.instant().getEpochSecond();
            if (now - checkedAt < CACHE_SECONDS) {
                return reachable;
            }
            boolean ok;
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), TIMEOUT_MILLIS);
                ok = true;
            } catch (Exception e) {
                ok = false;
            }
            reachable = ok;
            checkedAt = now;
            return ok;
        }
    }
}
