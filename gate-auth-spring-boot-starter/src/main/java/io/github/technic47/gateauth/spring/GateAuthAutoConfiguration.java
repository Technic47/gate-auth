package io.github.technic47.gateauth.spring;

import io.github.technic47.gateauth.core.ReplayGuard;
import jakarta.servlet.SessionCookieConfig;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.security.autoconfigure.web.servlet.ConditionalOnDefaultWebSecurity;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Clock;

/**
 * Gate Auth for servlet apps. Adds a default {@code SecurityFilterChain} (everything requires login) unless the
 * app defines its own; then use {@link GateAuthSecurity#configure(HttpSecurity)} in it.
 */
@AutoConfiguration(before = {ServletWebSecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(GateAuthProperties.class)
public class GateAuthAutoConfiguration {

    /** Created by Spring Boot's auto-configuration. */
    public GateAuthAutoConfiguration() {
    }

    @Bean
    GateAuthSettings gateAuthSettings(GateAuthProperties properties) {
        return new GateAuthSettings(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    ReplayGuard gateAuthReplayGuard() {
        return new ReplayGuard();
    }

    @Bean
    @ConditionalOnMissingBean
    GateReachability gateAuthReachability(GateAuthSettings settings) {
        return settings.directEnabled() ? new GateReachability.Tcp(settings.gateUrl(), Clock.systemUTC()) : () -> false;
    }

    /** Role catalog sync from the gate (spec §4.5), only with {@code gate.auth.roles.enabled=true}. */
    @Bean
    @ConditionalOnProperty(name = "gate.auth.roles.enabled", havingValue = "true")
    @ConditionalOnMissingBean
    GateRoleCatalog gateRoleCatalog(GateAuthSettings settings, ApplicationEventPublisher events,
                                    ObjectProvider<Clock> clock) {
        return new GateRoleCatalog(settings, events, clock.getIfAvailable(Clock::systemUTC));
    }

    @Bean
    GateAuthSecurity gateAuthSecurity(GateAuthSettings settings, ReplayGuard replayGuard,
                                      GateReachability reachability, ObjectProvider<Clock> clock,
                                      ObjectProvider<GateRoleCatalog> roles) {
        return new GateAuthSecurity(settings, replayGuard, reachability, clock.getIfAvailable(Clock::systemUTC),
                roles.getIfAvailable());
    }

    @Bean
    @ConditionalOnDefaultWebSecurity
    SecurityFilterChain gateAuthSecurityFilterChain(HttpSecurity http, GateAuthSecurity gateAuth) throws Exception {
        gateAuth.configure(http);
        http.authorizeHttpRequests(a -> a.anyRequest().authenticated());
        return http.build();
    }

    /** Session cookie per spec §6.5/§9: app-prefixed name, HttpOnly, Secure, SameSite=Lax, persistent. */
    @Bean
    ServletContextInitializer gateAuthSessionCookie(GateAuthSettings settings) {
        return servletContext -> {
            SessionCookieConfig cookie = servletContext.getSessionCookieConfig();
            cookie.setName(settings.sessionCookieName());
            cookie.setHttpOnly(true);
            cookie.setSecure(settings.cookieSecure());
            cookie.setAttribute("SameSite", "Lax");
            long ttl = Math.max(settings.props().direct().sessionTtl().toSeconds(),
                    settings.props().local().sessionTtl().toSeconds());
            cookie.setMaxAge((int) Math.min(Integer.MAX_VALUE, ttl));
        };
    }

    /** Stops Boot from creating its default in-memory user with a generated password; logins go through the gate. */
    @Bean
    @ConditionalOnMissingBean(UserDetailsService.class)
    UserDetailsService gateAuthNoUserDetails() {
        return username -> {
            throw new UsernameNotFoundException("Users are managed by the gate");
        };
    }
}
