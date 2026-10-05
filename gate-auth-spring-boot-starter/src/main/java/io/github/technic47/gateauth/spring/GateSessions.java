package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.AuthMode;
import io.github.technic47.gateauth.core.GateUser;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import java.time.Clock;

/**
 * App-side sessions for direct and local logins (spec §6.5). Edge mode never creates one.
 */
final class GateSessions {

    static final String LOGIN_AT = "gateauth.loginAt";
    static final String LAST_CHECKED = "gateauth.lastChecked";
    static final String RECHECK_ATTEMPT = "gateauth.recheckAttempt";
    static final String MODE = "gateauth.mode";

    private final GateAuthSettings settings;
    private final Clock clock;
    private final HttpSessionSecurityContextRepository repository = new HttpSessionSecurityContextRepository();
    private final SecurityContextHolderStrategy holder = SecurityContextHolder.getContextHolderStrategy();

    GateSessions(GateAuthSettings settings, Clock clock) {
        this.settings = settings;
        this.clock = clock;
    }

    /** New session (fixation-safe) holding this user. */
    void login(HttpServletRequest request, HttpServletResponse response, GateUser user) {
        HttpSession old = request.getSession(false);
        if (old != null) {
            old.invalidate();
        }
        HttpSession session = request.getSession(true);
        long ttl = settings.sessionTtl(user.mode()).toSeconds();
        session.setMaxInactiveInterval((int) Math.min(Integer.MAX_VALUE, ttl));
        long now = now();
        session.setAttribute(LOGIN_AT, now);
        session.setAttribute(LAST_CHECKED, now);
        session.setAttribute(MODE, user.mode().name());
        store(request, response, user);
    }

    /** Same session, refreshed user data (after a successful silent re-check). */
    void refresh(HttpServletRequest request, HttpServletResponse response, GateUser user) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            login(request, response, user);
            return;
        }
        session.setAttribute(LAST_CHECKED, now());
        session.removeAttribute(RECHECK_ATTEMPT);
        store(request, response, user);
    }

    void markChecked(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.setAttribute(LAST_CHECKED, now());
            session.removeAttribute(RECHECK_ATTEMPT);
        }
    }

    void logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
        holder.clearContext();
    }

    /** Ends the session if its absolute lifetime is over. @return true if it was ended */
    boolean expireIfOld(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return false;
        }
        Object loginAt = session.getAttribute(LOGIN_AT);
        Object mode = session.getAttribute(MODE);
        if (!(loginAt instanceof Long at) || !(mode instanceof String m)) {
            return false; // not ours
        }
        if (at + settings.sessionTtl(AuthMode.valueOf(m)).toSeconds() < now()) {
            session.invalidate();
            holder.setContext(holder.createEmptyContext());
            return true;
        }
        return false;
    }

    Long attribute(HttpServletRequest request, String name) {
        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(name) instanceof Long l ? l : null;
    }

    void setAttribute(HttpServletRequest request, String name, long value) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.setAttribute(name, value);
        }
    }

    long now() {
        return clock.instant().getEpochSecond();
    }

    private void store(HttpServletRequest request, HttpServletResponse response, GateUser user) {
        SecurityContext context = holder.createEmptyContext();
        context.setAuthentication(new GateAuthentication(user, settings.adminImpliesRoles()));
        holder.setContext(context);
        repository.saveContext(context, request, response);
    }
}
