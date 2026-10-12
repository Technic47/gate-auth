# gate-auth

One auth standard for all of the owner's apps, built around **GateService** (`../Gate Servise`).
The gate is the only place where users, passwords and per-app access live; apps only verify what the gate signed.

- Spec (normative): [`docs/gate-auth-spec-v1.md`](docs/gate-auth-spec-v1.md)
- Status: **0.1.0 is on Maven Central** (`io.github.technic47.gateauth`), all three modes implemented and tested.
  **0.2.0 (not yet released, 2026-10-12): role catalog** (§4.5): the gate defines roles (global or per app), apps
  sync them; several roles per user and app; `rv` claim. Needs GateService 0.3.0.
  GateService 0.2.0 issues the tokens and runs on the VPS since 2026-10-05 (key id `KENl1RAjjHUDtdGm`, public key at
  `https://144.31.187.7/.well-known/jwks.json`). No app uses the starter yet; newBikeService will be the first.
- Repository: `https://github.com/Technic47/gate-auth`

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
| `gate-auth-spring-boot-starter` | Spring Boot 4.1 / Spring Security 7.1 servlet starter: filters for all modes, `/auth/*` endpoints, CSRF (SPA cookie + header) and Origin checks, session handling, role catalog sync (`GateRoleCatalog`, 0.2.0) |

Coordinates: `io.github.technic47.gateauth:<artifact>:0.1.0` (Maven Central). Java 25, Spring Boot 4.1 / Spring
Security 7.1 for the starter. Apps on Boot 3 or older Java can't use it.

## Build

No Maven in PATH; use the one bundled with IntelliJ and the GraalVM 25 JDK:

```bash
export JAVA_HOME="/c/Users/Techn/.jdks/graalvm-jdk-25"
MVN="/c/Program Files/JetBrains/IntelliJIdea2026.1/plugins/maven/lib/maven3/bin/mvn"
"$MVN" -B install          # builds, tests (57 tests), installs to ~/.m2
```

Maven must **run on JDK 25** (the build enforces it). `-Prelease -Dgpg.skip verify` checks the release artifacts
(sources, javadoc) without signing.

## Release to Maven Central

Same setup as the Shop libraries (`central` server + GPG key in `~/.m2/settings.xml`), but the publishing plugins
live in the **`release` profile**, so normal builds don't need GPG (GateService's Docker build used to `install`
`gate-auth-core` without a key).

1. Bump the version in all three POMs (e.g. `mvn versions:set -DnewVersion=0.2.0`). Central versions are immutable:
   a published version can never be changed or deleted.
2. From the **root** folder (not a module), on **JDK 25**:
   ```bash
   "$MVN" -Prelease clean deploy
   ```
   In IntelliJ: Maven tool window → *Profiles* → tick **release**, run `clean` + `deploy` on the root **gate-auth**
   node. The Maven runner must use JDK 25 (*Settings → Build Tools → Maven → Runner → JRE*); the build stops early
   with a clear message otherwise.
3. One upload contains `gate-auth-parent` (POM), `gate-auth-core` and the starter (jar, sources, javadoc, `.asc`).
   Press **Publish** in the Central Portal; files appear on `repo1.maven.org` within ~10–30 minutes.

Plain `deploy` without `-Prelease` fails with "repository element was not specified" — that's the missing profile.

Signing key `F36407120C3EECF9` has an expiry date (it ran out on 2026-10-10 and was extended on 2026-10-13). An
expired key shows up as `gpg: signing failed` (in Russian locale garbled, "Отсутствует секретный ключ"). Fix:
`gpg --quick-set-expire <fingerprint> 2y` (and `'*'` for subkeys), then
`gpg --keyserver keyserver.ubuntu.com --send-keys <fingerprint>` so Central sees the new date.

## Generate the gate key

With Java 25 (plain `java` on the owner's PC is 21). PowerShell, using the jar from the local Maven repository:

```powershell
& "$env:USERPROFILE\.jdks\graalvm-jdk-25\bin\java.exe" -cp "$env:USERPROFILE\.m2\repository\io\github\technic47\gateauth\gate-auth-core\0.1.0\gate-auth-core-0.1.0.jar" io.github.technic47.gateauth.core.KeyTool
```
Prints the **private JWK** (secret: GateService only, as `GATE_SIGNING_KEY='{…}'` in its `.env`, single quotes) and
the **public key** as PEM and JWKS (for apps, `gate.auth.public-keys`). Each run makes a new key.

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

### Roles from the gate (0.2.0, spec §4.5)
The gate is the only place where roles are defined: global roles (assignable in every app) and app-specific ones;
a user can have several roles per app. The app syncs the list the gate offers it:

```yaml
gate:
  auth:
    roles:
      enabled: true
      gate-url: https://144.31.187.7        # default: direct.gate-url
      refresh: 10m                          # plus at once when a token carries a newer rv (max. once a minute)
      handled: [viewer, editor, admin]      # optional: codes the app implements; differences are logged
```

- `GateRoleCatalog` (bean): `current()` = the last verified catalog (code, name, description, global), `displayName(code)`.
- `@EventListener GateRolesChangedEvent` fires when a newer catalog arrives (e.g. to show new roles as "not configured").
- **Authorization still uses the token's `roles`** (`ROLE_<CODE>`); the catalog only adds names and change events.
  A role the app doesn't handle must grant nothing. While the gate is unreachable the last catalog stays.
- The gate's self-signed TLS certificate is accepted for this one request (`trust-any-tls-certificate: true`,
  default): the catalog is signed with the gate key and verified, so the content can't be forged.

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
2. GateService side ✓ — GateService 0.2.0, deployed on the VPS 2026-10-05
3. Library ✓ — 0.1.0 on Maven Central
4. Direct + local modes ✓ (library side; not yet tried end-to-end with a real app and browser)
5. **Next:** newBikeService adopts it (replaces Keycloak)
6. Role catalog (spec §4.5) — library 0.2.0 done 2026-10-12 (not released); GateService 0.3.0 in progress

FashionMark deliberately does **not** use the library (decided 2026-10-05): a single-user personal tool behind the
gate needs no in-app identity. It was upgraded to Boot 4 / Java 25 anyway, so it could adopt it later.
