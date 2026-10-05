# CLAUDE.md — gate-auth

Shared auth standard + Java library for all of the owner's apps behind **GateService** (`../Gate Servise`).

## Status
- **0.1.0 published on Maven Central** (2026-10-05). Versions on Central are immutable: never re-release a version,
  bump it. Release steps: README, "Release to Maven Central".
- GateService 0.2.0 issues tokens on the VPS (`kid=KENl1RAjjHUDtdGm`). No app uses the starter yet; newBikeService
  is the first. FashionMark deliberately doesn't use it.
- Repo: `https://github.com/Technic47/gate-auth`.

## Read first
- `docs/gate-auth-spec-v1.md` is **normative**. Code follows the spec; when behaviour changes, update the spec in the
  same change.
- `README.md`: usage, build, status.

## Fixed decisions (don't re-propose alternatives)
- GateService stays small (VPS: 1 vCPU / 2 GB). **No OIDC server / Spring Authorization Server in the gate.**
  Direct mode is the custom OIDC-subset redirect (`id_token` + `form_post`).
- No Keycloak.
- Tokens: Ed25519 (`alg=EdDSA`) JWS, JDK crypto only. `gate-auth-core` has **no dependencies** (own small JSON).
- Three modes (edge / direct / local), each switched per app in config, applied on restart (no runtime toggle).
- No domain: everything by bare IP + port. All apps on one IP share cookies → app-prefixed cookie names,
  Origin check + CSRF token on every unsafe request, even in edge mode.
- Spec and library live here, in their own folder (not inside GateService or newBikeService).

## Layout
```
docs/gate-auth-spec-v1.md
gate-auth-core/                  io.github.technic47.gateauth.core    (plain Java)
gate-auth-spring-boot-starter/   io.github.technic47.gateauth.spring  (Boot 4.1, Security 7.1, servlet)
```

## Build / test
```bash
export JAVA_HOME="/c/Users/Techn/.jdks/graalvm-jdk-25"
"/c/Program Files/JetBrains/IntelliJIdea2026.1/plugins/maven/lib/maven3/bin/mvn" -B install
```
Maven must run on JDK 25 (enforcer rule in the root POM). The owner's default `java`/`JAVA_HOME` is JDK 21, and
IntelliJ's Maven runner had to be switched to `graalvm-jdk-25`. Publishing plugins are in the `release` profile.

## Gotchas already hit
- Don't use spring-security-test's `csrf()` post-processor in the starter tests: it replaces the CSRF repository
  inside the shared `CsrfFilter`, which leaks into later tests (sessions appear, XSRF cookie disappears). Tests fetch
  the real `<APP>_XSRF` cookie instead, and MockMvc runs the real `springSecurityFilterChain` (no `springSecurity()`).
- The handoff cookie must be `SameSite=None; Secure`: the callback is a cross-site POST from the gate.
- An invalid `X-Gate-Assertion` must answer 401 and never fall back to the session (spec §8).
- Release from the root folder with `-Prelease`; plain `deploy` fails ("repository element was not specified").
- Javadoc: one-line `/** @param … @return … */` comments are not parsed; write multi-line javadoc. An annotation
  between the javadoc and the method hides the javadoc.
