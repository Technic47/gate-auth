# gate-auth

One auth standard for all of the owner's apps, built around **GateService** (`../Gate Servise`).
The gate is the only place where users, passwords and per-app access live; apps only verify what the gate signed.

- Spec (normative): [`docs/gate-auth-spec-v1.md`](docs/gate-auth-spec-v1.md)
- Status: library **0.1.0**, all three modes implemented and tested. GateService issues the tokens on
  branch `common_auth` (not deployed yet).

## Modes

| Mode | When | How |
|---|---|---|
| **edge** | Access through the VPS | nginx `auth_request` → gate adds signed `X-Gate-Assertion` → app verifies. No app session |
| **direct** | Access on the LAN | app sends the browser to the gate once (`/auth/handoff`, OIDC-subset form_post) → app keeps its own session (30 d), re-checks daily |
| **local** | Gate unreachable (break-glass) | accounts in app config, allowed networks only, lockout, off by default |

Each mode is switched on/off per app in config (restart to apply); one app can run all three at once.

## Modules

| Artifact | Contents |
|---|---|
| `gate-auth-core` | Plain Java 25, **no dependencies**. Ed25519 JWS sign/verify (JDK only), `GateClaims`, `GateUser`, key parsing (PEM / JWK / JWKS), `ReplayGuard`, `KeyTool`. Used by apps **and** by GateService (signer) |
| `gate-auth-spring-boot-starter` | Spring Boot 4.1 / Spring Security 7.1 servlet starter: filters for all modes, `/auth/*` endpoints, CSRF (SPA cookie + header) and Origin checks, session handling |

Coordinates: `io.github.technic47.gateauth:<artifact>:0.1.0`.

## Build

No Maven in PATH; use the one bundled with IntelliJ and the GraalVM 25 JDK:

```bash
export JAVA_HOME="/c/Users/Techn/.jdks/graalvm-jdk-25"
MVN="/c/Program Files/JetBrains/IntelliJIdea2026.1/plugins/maven/lib/maven3/bin/mvn"
"$MVN" -B install          # builds, tests (57 tests), installs to ~/.m2
```

Release to Maven Central: `"$MVN" -Prelease deploy` (GPG + central-publishing, same as the Shop starter).

## Generate the gate key

```bash
java -cp gate-auth-core/target/gate-auth-core-0.1.0.jar io.github.technic47.gateauth.core.KeyTool
```
Prints the **private JWK** (secret, GateService only, `GATE_SIGNING_KEY_FILE`) and the **public key** as PEM and
JWKS (for apps, `gate.auth.public-keys`).

## Use in an app

```xml
<dependency>
    <groupId>io.github.technic47.gateauth</groupId>
    <artifactId>gate-auth-spring-boot-starter</artifactId>
    <version>0.1.0</version>
</dependency>
```

Edge only (e.g. FashionMark, reachable only through the VPS):

```yaml
gate:
  auth:
    app-name: fashionmark                     # = X-Service-Name in nginx = service name in the gate
    public-urls: [https://144.31.187.7:8843]
    public-keys: ${GATE_PUBLIC_KEY}           # PEM from KeyTool
    edge.enabled: true
```

VPS + LAN (+ break-glass), e.g. newBikeService:

```yaml
server:
  forward-headers-strategy: native            # behind Caddy/nginx: correct scheme/host/port and client IP
gate:
  auth:
    app-name: bikeservice
    public-urls: [https://144.31.187.7:8845, https://192.168.1.50:8443]
    public-keys: ${GATE_PUBLIC_KEY}
    admin-implies-roles: [admin]
    local-secret: ${GATE_AUTH_LOCAL_SECRET}   # openssl rand -base64 48
    edge.enabled: true
    direct:
      enabled: true
      gate-url: https://144.31.187.7
    local:
      enabled: false                          # true only while the gate is unreachable
      allowed-networks: [192.168.1.0/24]
      users:
        - { name: admin, hash: "${LOCAL_ADMIN_HASH}", roles: [admin], link-to: "1" }
```

Without your own `SecurityFilterChain`, everything requires login. With your own chain:

```java
@Bean
SecurityFilterChain security(HttpSecurity http, GateAuthSecurity gateAuth) throws Exception {
    gateAuth.configure(http);
    http.authorizeHttpRequests(a -> a
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated());
    return http.build();
}
```

In controllers: `@AuthenticationPrincipal GateUser user` → `user.subject()` (stable id: key your data on it),
`user.username()`, `user.roles()`, `user.mode()`.

### For the SPA
- `GET /auth/me` → current user, or 401 with `login_url`.
- Any API 401 has `login_url`: `location.href = login_url + "?redirect=" + encodeURIComponent(location.pathname + location.search)`.
- Writes (`POST/PUT/PATCH/DELETE`): read cookie `<APP>_XSRF`, send it as header `X-XSRF-TOKEN`. The browser's
  `Origin` must be one of `public-urls`.
- Logout: `POST /auth/logout` (with the XSRF header) ends the LAN session; the answer's `gate_logout_url` logs out of
  the gate (all apps).

## Things to know
- **Sessions are in memory** (servlet sessions). After an app restart, LAN users go through the gate again (one
  redirect, usually no password if the gate session is alive). Add Spring Session JDBC in the app if that bothers you.
- **One instance per app**: the handoff replay guard and the local-login lockout are in memory.
- **All apps on one IP share cookies** (ports don't separate them). Cookie names are app-prefixed; never log
  `Cookie` / `X-Gate-Assertion` headers.
- The session cookie's `SameSite=Lax` is set through the servlet `SessionCookieConfig` (Tomcat writes it).

## Order of work
1. Spec ✓
2. GateService side ✓ — branch `common_auth` in `../Gate Servise` (not deployed yet)
3. Library ✓, first tried on FashionMark (edge only)
4. Direct + local modes ✓ (library side)
5. newBikeService adopts it (replaces Keycloak)
