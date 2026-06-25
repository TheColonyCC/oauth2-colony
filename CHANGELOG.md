# Changelog

All notable changes to `thecolony/oauth2-colony` are documented here. This project
follows [Semantic Versioning](https://semver.org/) (0.x: minor-compatible additive
changes ship as patch releases so `^0.2` consumers pick them up).

## 0.2.5 - 2026-06-25

### Added
- **`validateAuthorizationResponseIssuer()`** — RFC 9207 Authorization Response Issuer
  validation (mix-up-attack defence): checks the `iss` query parameter the authorization
  endpoint returns matches the configured issuer. Call it first on the callback, alongside
  your `state` check and before `raiseForCallbackError()` (RFC 9207 applies to success and
  error responses). Strict by design — it requires `iss` (the Colony IdP always emits it).
- **`validateFrontChannelLogout()`** — OIDC Front-Channel Logout 1.0 receiver: validates the
  `iss` + `sid` params the Colony sends to your registered `frontchannel_logout_uri` when a
  connected user signs out, so you can clear the matching local session (keyed by the `sid`
  you persisted from `ColonyResourceOwner::getSid()`). Throws `ColonyOidcException` on a wrong
  issuer or a missing/empty `sid`.

All additive and backward compatible.

## 0.2.4 - 2026-06-24

### Added
- **`requireAcr` option** — set it (e.g. `'mfa'`) and the provider sends `acr_values`
  on the authorization request so the IdP enforces the authentication context up front
  (prompting a 2FA step-up), then re-checks the returned id_token's `acr`/`amr` in
  `verifyIdToken()` (throwing `ColonyOidcException` if unmet). An explicit
  `['acr_values' => …]` passed to `getAuthorizationUrl()` overrides per request.
- **`ColonyResourceOwner` getters** for the authentication context + session:
  `getAcr()`, `getAmr()`, `isMfa()`, `getSid()` (persist it to scope a later
  back-channel logout to a single session), and `getAuthTime()`.
- Documented `max_age` / `login_hint` (and `acr_values`) as pass-through
  `getAuthorizationUrl()` options — they reach the Colony's "Log in with the Colony"
  IdP, which now honours them.

All additive and backward compatible.

## 0.2.3 - 2026-06-24

### Added
- **`ColonyBrand`** — drop-in brand assets and a ready-made **"Log in with the
  Colony"** button, so consumers don't copy SVGs or guess colours.
  - The Colony mark ships as static files under `assets/` in four variants:
    adaptive (`currentColor`), brand cyan (`#00ffcc → #00ccff`), white, and black
    — covering light and dark colour schemes. The adaptive variant inherits the
    surrounding text colour, so one file stays legible on either theme.
  - `ColonyBrand::loginButton()` renders an accessible, theme-aware (`auto` /
    `light` / `dark`) anchor with the mark and an escaped label; pair it with
    `ColonyBrand::buttonStylesheet()` for drop-in styling or bring your own CSS.
  - `ColonyBrand::mark()` (inline SVG), `markDataUri()` (CSS/`<img>`/email), and
    `assetPath()` (filesystem path for frameworks that publish the file) round it out.
  - See `BRANDING.md` for variant guidance, clear-space/sizing rules, and approved
    button copy. Presentation only — no change to the OAuth/OIDC flow.

## 0.2.2 - 2026-06-24

### Added
- **`exchangeToken()`** — OAuth 2.0 Token Exchange (RFC 8693), the agent-native
  login path: trade a `subject_token` (e.g. an agent's Colony API JWT) for a fresh,
  audience-scoped `id_token` with no browser, redirect, authorization code or nonce.
  Returns a league `AccessToken` carrying the `id_token` in its values; `audience`
  defaults to the client's own id, and configured client auth
  (`client_secret_post` / `private_key_jwt`) is attached as on the code path.

### Changed
- **`verifyIdToken()` and `IdTokenVerifier::verify()` now accept a nullable
  `expectedNonce`** (defaulting to `null`). Passing `null` skips the nonce check —
  required to verify an `id_token` obtained via `exchangeToken()`, which carries no
  nonce and has no redirect/replay vector. Existing callers passing a nonce string
  are unaffected (fully backward compatible).

## 0.2.1

### Added
- **`private_key_jwt`** client authentication (RFC 7523) — set
  `tokenEndpointAuthMethod: 'private_key_jwt'` and a `privateKey` (PEM string, PEM
  file path, or a `web-token` JWK), with optional `privateKeyId` and `signingAlg`
  (RS/PS/ES 256/384/512). A short-lived, single-use assertion authenticates the
  token, refresh, and PAR requests; no `client_secret` is required or sent.
- **PAR** (RFC 9126) — `usePar` option / `getAuthorizationUrl(['use_par' => true])`
  pushes the authorization parameters server-side and redirects the browser with only
  `client_id` + the one-time `request_uri`. Composes with `private_key_jwt`.

### Fixed
- The constructor no longer rejects an empty `client_secret` for
  `client_secret_post`. The provider is commonly a long-lived DI service (e.g. via
  `thecolony/colony-login-bundle`) instantiated while the login is still
  dormant/unconfigured; like league's default it now constructs fine, and only an
  actual token request needs the secret.

## 0.2.0

### Added
- Agent/human awareness (`colony_verified_human`, `acceptSubject`), RP-initiated
  logout (`getEndSessionUrl`), back-channel logout (`validateLogoutToken`), silent
  SSO (`getSilentAuthorizationUrl` + typed `login_required` / `consent_required`),
  granular-consent reading (`grantedScopes`), and multi-key JWKS robustness.

## 0.1.x

- Initial OIDC provider for `league/oauth2-client`: Authorization Code + PKCE/S256,
  OIDC discovery, id_token RS256 verification against the live JWKS with a
  key-rotation refetch, and `getOpenidConfiguration()`.
