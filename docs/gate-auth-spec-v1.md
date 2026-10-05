# Gate Auth v1 — Specification

- Status: **Draft**
- Date: 2026-10-05
- Applies to: GateService (`../Gate Servise`) and every app that uses the `gate-auth` library

The key words MUST, MUST NOT, SHOULD, MAY are used as in RFC 2119.

---

## 1. Purpose

One way for all of the owner's apps to know **who the user is** and **what they may do**, with
**GateService** as the only place where users, passwords and per-app access are managed.

Constraints this design follows:
- GateService runs on a small VPS (1 vCPU, 2 GB RAM). Gate changes must stay small. **No OIDC server in the gate.**
- Apps run on the home server behind a reverse SSH tunnel. They are reachable via the VPS (internet) and
  directly on the LAN.
- No domain names. Everything is addressed by bare IP + port, so all apps on one IP share one browser cookie jar.
- The home server may be unable to reach the VPS (internet down). The browser is the only party guaranteed to
  see both sides during a login.

## 2. Terms

| Term | Meaning |
|---|---|
| **Gate** | GateService on the VPS. Issues and signs all tokens |
| **App** | Any project that uses this standard (FashionMark, newBikeService, …) |
| **app-name** | The app's unique id. Equals `ProtectedService.name` in the gate, the `X-Service-Name` header in nginx and the `aud` claim |
| **Edge mode** | Request comes through VPS nginx; the gate's verdict arrives as a signed header |
| **Direct mode** | User opens the app on the LAN; the app sends the browser to the gate once, then keeps its own session |
| **Local mode** | Break-glass login with accounts configured in the app itself, for when the gate is unreachable |
| **Assertion** | Short-lived signed token sent on every edge-mode request (`typ: gate-assertion+jwt`) |
| **Handoff token** | Short-lived signed token that ends a direct-mode login (`typ: gate-handoff+jwt`) |

## 3. Keys

- Algorithm: **Ed25519** (JWS `alg: EdDSA`, JWK `kty: OKP`, `crv: Ed25519`).
- The **private key exists only in the gate** (PKCS#8 PEM file, path in `GATE_SIGNING_KEY_FILE`). It is never
  committed, never logged, never copied to apps.
- `kid` = RFC 7638 JWK thumbprint (base64url SHA-256), first 16 characters.
- The gate publishes all currently valid public keys at **`GET /.well-known/jwks.json`** (no auth, cacheable 1 h).
- Apps are configured with the public key(s) **statically** (PEM or JWK in env/config). Apps MAY additionally
  refresh from the JWKS URL when reachable; a static key MUST work without the gate being reachable.
- **Rotation**: (1) generate new key, publish both in JWKS and add the new public key to every app;
  (2) switch the gate to sign with the new key; (3) after the longest token lifetime + margin (> 1 h), remove the old
  key from apps and JWKS.

## 4. Tokens

Both token types are JWS compact serialization (`header.payload.signature`).

### 4.1 Header
```json
{ "alg": "EdDSA", "kid": "<kid>", "typ": "gate-assertion+jwt" }   // or "gate-handoff+jwt"
```
Different `typ` values stop a token issued for one purpose from being accepted for the other.

### 4.2 Claims

| Claim | Type | Assertion | Handoff | Meaning |
|---|---|:-:|:-:|---|
| `v` | int | ✓ | ✓ | Standard version. Always `1` |
| `iss` | string | ✓ | ✓ | Gate id, configured (default `"gate"`) |
| `sub` | string | ✓ | ✓ | Gate user id (`users.id` as a decimal string). **Stable; apps key users on it, never on the username** |
| `preferred_username` | string | ✓ | ✓ | Current username (may change; display only) |
| `aud` | string | ✓ | ✓ | The single app-name this token is for |
| `gate_role` | string | ✓ | ✓ | Global gate role: `ADMIN` or `USER` |
| `roles` | string[] | ✓ | ✓ | Roles **inside this app**, from the gate's per-app grant (e.g. `["admin"]`). Empty array allowed |
| `svc` | string[] | ✓ | ✓ | app-names the user may open (for an app switcher). Informational only |
| `iat` | int | ✓ | ✓ | Issued at (epoch seconds) |
| `exp` | int | ✓ | ✓ | Expiry. Assertion: `iat + 60`. Handoff: `iat + 120` |
| `jti` | string | ✓ | ✓ | Random id (≥ 128 bits, base64url) |
| `sid` | string | ✓ | ✓ | Hash of the gate session id (not the session id itself). Lets apps correlate logs |
| `nonce` | string | | ✓ | Copied from the direct-mode request |
| `auth_time` | int | | ✓ | When the user last entered a password at the gate |

Claim names follow OIDC where one exists, so a later move to a real OIDC provider keeps the same claims.

### 4.3 Validation (apps MUST do all, in this order)
1. Exactly three parts; header parses; `alg` is exactly `EdDSA` (reject anything else, including `none`).
2. `typ` matches the expected type for this place (header → assertion, callback → handoff).
3. `kid` is one of the configured keys; signature verifies.
4. `v == 1`; `iss` equals configured issuer; `aud` equals this app's app-name.
5. `exp` > now − 30 s skew; `iat` < now + 30 s; `exp − iat` ≤ 300.
6. Handoff only: `nonce` matches (§6.4), `jti` not seen before (§6.4).
7. `sub` non-empty; `roles` and `svc` are arrays of strings.

Any failure → the token is rejected as a whole. Apps MUST NOT fall back to another mode after a failed token (§8).

Both hosts MUST run NTP; tokens are short-lived and clock drift breaks them.

### 4.4 Roles
- The gate stores at most one role per user-app grant (table `user_service_role`, kept only while the
  access grant exists).
- `roles` = that grant's role as a one-element array, or `[]` if the grant has no role.
- A gate `ADMIN` with no explicit grant who passes via `adminBypassesAccess` gets `roles: []` and
  `gate_role: "ADMIN"`. Each app decides in config whether `gate_role=ADMIN` implies an app role
  (library property `gate.auth.admin-implies-roles`).
- Role names are app-defined lowercase strings. Apps map them to authorities `ROLE_<UPPERCASE>`.

## 5. Edge mode (via VPS)

```
Browser ─► VPS nginx :<app port> ─auth_request─► Gate /verify
                    │ ◄── 200 + X-Gate-Assertion: <jwt>   (or 401 / 403)
                    └─ proxy ─► tunnel ─► home ─► App (verifies X-Gate-Assertion)
```

### 5.1 Gate
- `/verify` keeps its current decision logic (DB check on every request = instant revocation).
- On 200 it adds **`X-Gate-Assertion`** signed for `aud = X-Service-Name`.
- The gate MAY cache the signed assertion per (session, app) and reuse it while it has ≥ 30 s left.
- `X-Gate-User` / `X-Gate-Role` stay for compatibility but apps using this standard MUST ignore them.

### 5.2 nginx (generated by the gate's config generator)
```nginx
location = /_gate_verify {
    internal;
    proxy_pass http://127.0.0.1:9000/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Service-Name "<app-name>";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Forwarded-For $remote_addr;
}

# API calls from SPAs: answer 401/403 as JSON, never redirect (fetch would follow it to an HTML login page)
location /api/ {
    auth_request /_gate_verify;
    auth_request_set $gate_assertion $upstream_http_x_gate_assertion;
    proxy_set_header X-Gate-Assertion $gate_assertion;   # always overwrites a client-sent value
    error_page 401 = @gate_api_401;
    error_page 403 = @gate_api_403;
    proxy_pass <upstream>;
}

location / {
    auth_request /_gate_verify;
    auth_request_set $gate_assertion $upstream_http_x_gate_assertion;
    proxy_set_header X-Gate-Assertion $gate_assertion;
    error_page 401 = @gate_login;
    error_page 403 = @gate_denied;
    proxy_pass <upstream>;
}

location @gate_api_401 {
    default_type application/problem+json;
    return 401 '{"type":"about:blank","title":"Unauthorized","status":401,"login_url":"https://<gate>/login"}';
}
location @gate_api_403 {
    default_type application/problem+json;
    return 403 '{"type":"about:blank","title":"Forbidden","status":403}';
}
```
The API prefix is per app (configured on the gate's `ProtectedService`, default `/api/`).
The SPA, on 401 with `login_url`, sets `window.location = login_url + "?redirect=" + encodeURIComponent(location.href)`.

### 5.3 App
- No session is created in edge mode. Every request is authenticated by its own assertion.
- Long requests (SSE, uploads) are authenticated once at the start; the 60 s expiry does not cut them.

## 6. Direct mode (LAN)

Shape: a strict subset of OIDC Core *Implicit Flow* with `response_type=id_token` and
*OAuth 2.0 Form Post Response Mode*. Only the browser talks to both sides; the home app never calls the VPS.

```
Browser ─► App (LAN)  no session
   ◄── 302  https://<gate>/auth/handoff?…state…nonce…   + handoff cookie
Browser ─► Gate /auth/handoff   (login form first if no gate session)
   ◄── 200  auto-submitting form  POST <redirect_uri>  {id_token, state}
Browser ─► App /auth/callback   verify → create local session
   ◄── 302  original page
```

### 6.1 Gate registration (per app, in `ProtectedService`)
- `directEnabled` (bool, default false).
- `redirectUris` (list of exact strings, e.g. `https://192.168.1.50:8443/auth/callback`). **Exact match only**:
  no prefix, no wildcard, no normalization beyond what `java.net.URI` parsing rejects.

### 6.2 Authorization request (app → gate, via browser redirect)
`GET https://<gate>/auth/handoff` with query parameters:

| Param | Required | Value |
|---|:-:|---|
| `response_type` | ✓ | `id_token` |
| `response_mode` | ✓ | `form_post` |
| `client_id` | ✓ | app-name |
| `redirect_uri` | ✓ | one of the registered URIs |
| `state` | ✓ | 32 random bytes, base64url |
| `nonce` | ✓ | 32 random bytes, base64url |
| `prompt` | | `none` = silent re-check: never show the login form (§6.6) |

### 6.3 Gate handling
1. `response_type`/`response_mode` exact; `client_id` is an enabled service with `directEnabled`;
   `redirect_uri` is registered for it. Any of these wrong → **show an error page at the gate, never redirect**
   (an unverified `redirect_uri` must never receive anything).
2. `state` and `nonce`: 16–128 chars of `[A-Za-z0-9_-]`, else error page.
3. No gate session: `prompt=none` → respond with `error=login_required`; otherwise show the login form and
   continue at step 4 after login (the return target is the relative `/auth/handoff?…` path, allowed by `RedirectTargets`).
4. User blocked or has no access to the app → respond with `error=access_denied`.
5. Success → respond with `id_token=<handoff token>` (aud = client_id, nonce copied).
6. Log `HANDOFF_ISSUED` / `HANDOFF_DENIED` in the activity log.

**Response page** (both success and error): an HTML page with one form, `method=post`,
`action=<redirect_uri>`, hidden fields `id_token` or `error`, and `state`, auto-submitted by a tiny inline script
with a "Continue" button as no-JS fallback. All values HTML-attribute-escaped. Headers:
`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `Content-Security-Policy: default-src 'none';
script-src 'sha256-<hash of the inline script>'; form-action <redirect_uri origin>`, `X-Frame-Options: DENY`.

### 6.4 App side
**Starting the login**
- Create `state`, `nonce` and the return path (relative path only, from the original request).
- Store them in the **handoff cookie** `<APP>_HANDOFF` = base64url(JSON `{state, nonce, ret, exp}`) + `.` +
  HMAC-SHA256 with the app's local secret. Attributes: `HttpOnly; Secure; SameSite=None; Path=/auth/callback;
  Max-Age=600`. **`SameSite=None` is required**: the callback is a cross-site POST from the gate's origin, and
  `Lax`/`Strict` cookies are not sent on it.
- 302 to the gate.

**Callback `POST /auth/callback`**
1. Read and HMAC-verify the handoff cookie; not expired. Delete it in the response (one use).
2. Form `state` equals cookie `state` (constant-time compare). Mismatch → 400, no session.
3. If `error` is present → show "login failed / access denied" page, no session.
4. Validate `id_token` per §4.3 with `typ=gate-handoff+jwt`; `nonce` equals cookie `nonce`.
5. `jti` not seen before; remember it until `exp` (in-memory store is enough for one instance).
6. Create the app session (§6.5) and 302 to `ret`.

The callback endpoint is excluded from CSRF token checks (it is protected by `state`), but nothing else is.

### 6.5 App session
- Cookie `<APP>_SESSION`: `HttpOnly; Secure; SameSite=Lax; Path=/`. New session id on login (fixation).
- Stores: `sub`, `preferred_username`, `gate_role`, `roles`, `svc`, `auth_time`, `last_checked`, mode=`direct`.
- Absolute lifetime `session-ttl` (default 30 days). Sessions MAY survive app restarts (JDBC store) — app choice.

### 6.6 Re-check (silent)
When `now − last_checked > recheck-after` (default 24 h) and the request is a top-level page navigation (not API),
the app redirects with `prompt=none`:
- `id_token` returned → update roles/claims, `last_checked = now`.
- `error=access_denied` → **end the session** (user blocked or access revoked at the gate).
- `error=login_required` → keep the session (the user just has no gate session now), `last_checked = now`.
- Gate unreachable: the app first checks it can open a TCP connection to the gate's host:port (cached 60 s).
  If not, no redirect happens. Either way, a re-check is attempted at most once per `recheck-retry`
  (default 1 h), so a VPS outage never strands the user on a browser "connection failed" page more than
  once an hour. A user offline from the VPS keeps working until `session-ttl`.
API calls never trigger a re-check; they only see the session.

### 6.7 Logout
- `POST /auth/logout` (CSRF-protected) ends the app session only.
- The app's UI SHOULD also offer "Log out everywhere" → link to the gate's `GET /logout` confirmation page.

## 7. Local mode (break-glass)

- Accounts are listed in app config: `name`, bcrypt `hash`, `roles`, optional `link-to` (a gate `sub`).
  `link-to` makes the local user act as that gate user, so data owned by the owner's gate account is visible.
  Without it, `sub = "local:<name>"`.
- Login page served by the app at `/auth/local`. Same session cookie as §6.5 with mode=`local`, no re-check,
  and a shorter lifetime (`local.session-ttl`, default 12 h). `gate_role` of a local user is `LOCAL`.
- **Only from `allowed-networks`** (CIDR list, required). The client address is `request.getRemoteAddr()` as
  the servlet container resolved it, so the app's forwarded-header settings decide whether a proxy's
  `X-Forwarded-For` is used. Requests that arrived through the VPS tunnel MUST NOT resolve to an address in
  `allowed-networks`: check this when deploying behind the home proxy. (Through the VPS, nginx also requires a valid
  gate session before any request reaches the app.)
- Lockout: 5 failed attempts → 15 min lock per username + per IP.
- While local mode is enabled, the app logs a WARN line on every start.

## 8. Request resolution (all modes together)

For every request, in this order:
1. **`X-Gate-Assertion` present** (edge enabled) → validate. Valid → user. Invalid → **401, stop**.
   (Never fall through: an invalid header must not be "rescued" by a session cookie.)
   If edge is disabled and the header is present → ignore it.
2. **`<APP>_SESSION` valid** → user from the session.
3. **Nothing**:
   - API paths (`api-paths`, default `/api/**`) → 401 Problem Details with `login_url` = the app's own
     `/auth/login?redirect=…`.
   - Pages → `/auth/login`:
     - only direct enabled → straight to the gate (§6.4)
     - only local enabled → local login page
     - both → a chooser page ("Log in via Gate" / "Local login", the latter only shown from `allowed-networks`)
     - neither (edge-only app) → 401 page "open this app via `<public URL>`"

The resulting principal is always the same type (`GateUser`: `sub`, `username`, `gateRole`, `roles`, `svc`, `mode`),
so app code never cares which mode authenticated the request.

App endpoints (under `base-path`, default `/auth`):

| Endpoint | Purpose |
|---|---|
| `GET /auth/login?redirect=` | Login entry; picks direct / local / chooser as above |
| `GET /auth/direct?redirect=` | Start a direct (gate) login |
| `POST /auth/callback` | Direct-mode handoff answer (the gate's `redirect_uri`) |
| `GET`/`POST /auth/local` | Local login form / submit |
| `POST /auth/logout` | End the app session; returns `{"gate_logout_url": …}` |
| `GET /auth/me` | Current user as JSON (`sub`, `username`, `gate_role`, `roles`, `authorities`, `svc`, `mode`), or 401 |

## 9. Cookies, CSRF and the shared IP

- All apps on one IP share the browser cookie jar regardless of port. Therefore:
  - every app's cookies are prefixed with its own name (`BIKESERVICE_SESSION`, …);
  - apps MUST NOT log `Cookie` or `X-Gate-Assertion` headers (the gate's `GATESESSION` reaches every app);
  - all apps on the same IP are one trust zone: a compromised app can read the others' cookies.
- SameSite does not separate apps on the same IP (same site). So, for every state-changing request
  (`POST/PUT/PATCH/DELETE`), apps MUST:
  1. check `Origin` (or `Referer` if `Origin` is absent) is one of `public-urls`; and
  2. require a CSRF token (double-submit: cookie `<APP>_XSRF`, header `X-XSRF-TOKEN`).
  This applies in edge mode too: the gate session cookie is ambient, so edge requests are CSRF-able.
- Exception: `POST /auth/callback` (protected by `state`, §6.4).

## 10. Errors (app responses)

RFC 9457 Problem Details:
- 401 `{"title":"Unauthorized","status":401,"login_url":"…"}`
- 403 `{"title":"Forbidden","status":403}` (authenticated, missing role)
No reason detail that would help probing (signature vs expiry vs audience) goes to the client; it goes to the log.

## 11. Library configuration (reference)

```yaml
gate:
  auth:
    app-name: bikeservice                 # = aud = X-Service-Name = ProtectedService.name
    issuer: gate
    public-urls:                          # all origins the app is reached under (Origin check, redirects)
      - https://144.31.187.7:8845
      - https://192.168.1.50:8443
    api-paths: [/api/**]
    public-keys: ${GATE_PUBLIC_KEYS}      # one or more PEM/JWK; jwks-url optional refresh
    public-keys-location:                 # alternative: file/classpath resource with the same content
    admin-implies-roles: [admin]          # roles granted when gate_role=ADMIN; [] = none
    local-secret: ${APP_AUTH_SECRET}      # HMAC for handoff cookie; required if direct enabled (≥ 32 chars)
    base-path: /auth                      # library endpoints; callback = <base-path>/callback
    cookie-secure: true                   # false only for plain-http local development
    clock-skew: 30s
    edge:
      enabled: true
      header: X-Gate-Assertion
    direct:
      enabled: true
      gate-url: https://144.31.187.7
      session-ttl: 30d
      recheck-after: 24h
      recheck-retry: 1h
    local:
      enabled: false
      allowed-networks: [192.168.1.0/24]
      session-ttl: 12h
      max-failures: 5
      lockout: 15m
      users:
        - { name: admin, hash: ${LOCAL_ADMIN_HASH}, roles: [admin], link-to: "1" }
```
Cookie names are derived from `app-name`: `BIKESERVICE_SESSION`, `BIKESERVICE_XSRF`, `BIKESERVICE_HANDOFF`.
Modes switch on restart only (no runtime toggle). Startup MUST fail if: no mode enabled; edge/direct enabled without
`public-keys`; direct enabled without `local-secret` or `gate-url`; local enabled without `users` or `allowed-networks`.

## 12. Versioning

- Breaking changes → `v: 2` and new `typ` values. During migration the gate MAY issue both; apps accept only
  the versions they know.
- Additive claims do not change the version; apps MUST ignore unknown claims.

## 13. Required gate changes (summary)

1. Ed25519 signer (key file, `kid`), `/.well-known/jwks.json`.
2. `/verify`: add `X-Gate-Assertion` on 200.
3. Per-app role (`user_service_role` table) + admin UI field.
4. `ProtectedService`: `directEnabled`, `redirectUris`, `apiPrefix`.
5. `/auth/handoff` endpoint + response page (§6.3), activity log types `HANDOFF_ISSUED` / `HANDOFF_DENIED`.
6. Config generator: `/api/` location with JSON 401/403, forward `X-Gate-Assertion`.

Implemented in GateService, branch `common_auth` (2026-10-05): one table, three service columns, no new
infrastructure. Signing key: `GATE_SIGNING_KEY` (inline private JWK) or `GATE_SIGNING_KEY_FILE`; without a key the
gate keeps working without tokens.

## 14. Security notes

- Assertions are bearer tokens for 60 s. They only travel inside TLS (VPS nginx → tunnel → home proxy).
- Revocation: edge = instant (DB check per request); direct = at next re-check (≤ `recheck-after`) or session end.
  This delay is the accepted cost of LAN sessions that work offline.
- `aud` binding stops a token for one app being replayed against another.
- Handoff tokens pass through the browser: protected by `state` (CSRF on the callback), `nonce` (binding to the
  browser that started the login), `jti` (single use), 120 s expiry, POST body (not URL, so not in logs/history/Referer).
- The gate never redirects or posts to an unregistered `redirect_uri`.
- Local mode is the weakest path: network-restricted, lockout, WARN on start, off by default.

## 15. Implementation notes (non-normative)

- Ed25519 is in the JDK (`Signature.getInstance("Ed25519")`, `KeyFactory.getInstance("Ed25519")`, Java 15+).
  A hand-written compact-JWS sign/verify for exactly this one algorithm is ~100 lines and keeps `gate-auth-core`
  free of dependencies. If a JOSE library is used instead, check that its EdDSA support doesn't pull in heavy
  extra dependencies.
- The gate side reuses `RedirectTargets`-style `java.net.URI` parsing for `redirect_uri` checks, plus exact string
  equality against the registered list.

## 16. Open items

- Maven Central publishing of the library (coordinates: `io.github.technic47.gateauth:gate-auth-core` /
  `gate-auth-spring-boot-starter`).
- Several instances of one app: the replay guard and lockout counters are in memory (fine for one instance).
- Whether newBikeService's internal services verify the same assertion or the app's gateway re-issues an
  internal token (decided in newBikeService, not here).
- Android / native clients: not covered by v1. Options later: personal API tokens issued by the gate, or a real
  OIDC provider (would replace §6 with Authorization Code + PKCE; claims and §8 stay the same).
