/**
 * Spring Boot (servlet) starter for Gate Auth v1.
 *
 * <p>Configure it with {@code gate.auth.*} properties ({@link io.github.technic47.gateauth.spring.GateAuthProperties}).
 * Without an own {@code SecurityFilterChain} every request requires login; with one, call
 * {@link io.github.technic47.gateauth.spring.GateAuthSecurity#configure} in it. Controllers receive the user as
 * {@code @AuthenticationPrincipal GateUser}.
 *
 * <p>Three modes, each switched on separately: <b>edge</b> (signed {@code X-Gate-Assertion} header from VPS nginx),
 * <b>direct</b> (LAN login through the gate, then an app session) and <b>local</b> (break-glass accounts).
 */
package io.github.technic47.gateauth.spring;
