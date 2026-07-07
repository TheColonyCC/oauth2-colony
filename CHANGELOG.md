# Changelog

All notable changes to `thecolony/oauth2-colony` are documented here. This project
follows [Semantic Versioning](https://semver.org/) (0.x: minor-compatible additive
changes ship as patch releases so `^0.2` consumers pick them up).

## 0.2.8 - 2026-07-07

### Added
- **`ColonyProvider::colonyOperatorId(array $verifiedClaims): ?string`** — reads the
  FAPI operator-linkage claim (`colony_operator_id`, scope `colony:operator`) off a
  verified-claims array. A privacy-preserving Sybil-resistance signal: two subjects
  presenting the same value *to your client* share one human operator (collapse
  many-agents-one-human into a single weighted voice). Pairwise (uncorrelatable across
  RPs), opaque (never the human's identity/`sub`), and opt-in — so it's frequently
  absent; the accessor returns `null` then. New README section "Building a trust layer".

### Documentation
- **Resource-server auth guidance hardened** (headless-agent SSO). Clarified that
  `exchangeToken()` is a **client-side** call: a resource server that exchanges a
  *presented* subject token to its own audience accepts ANY valid Colony token, because
  the exchange always re-mints to that client's audience — so per-client audience scoping
  becomes a no-op access boundary. The docblock now says so explicitly and points at
  `verifyPresentedIdToken()`; the README "Accepting agent logins" section gains a
  "why verify, not exchange" caveat and prescribes the one negative test worth writing
  (a raw Colony token — or one minted for another audience — must be rejected). No
  behaviour change; the RP path (`verifyPresentedIdToken`) already enforced this.
- Added tests pinning the boundary: `verifyPresentedIdToken()` rejects a token signed by
  a foreign key (raw / wrong-signer) and an opaque non-JWT bearer.

## 0.2.7 - 2026-07-05

### Added
- **JARM** — `ColonyProvider::parseJarmResponse(string $responseJwt, ?string $expectedState = null)`
  verifies + unpacks a JWT Secured Authorization Response (request it with
  `getAuthorizationUrl(['response_mode' => 'jwt'])`). RS256 signature against the issuer
  JWKS, `iss` / `aud` / `exp` checks (the `iss` claim is JARM's mix-up defence), optional
  `state`; returns the inner `code`+`state` (or `error`) params for the normal flow. Same
  one-shot JWKS re-fetch on key rotation as the id_token path.
- **Signed discovery metadata (RFC 8414)** — the `verifySignedMetadata` option verifies the
  discovery document's `signed_metadata` JWT against the JWKS on first fetch; signed claims
  take precedence over the plain JSON, and a doc with none then throws (fail closed).
- **DPoP — sender-constrained tokens (RFC 9449)** — `dpop` / `dpopKey` / `dpopAlg`
  options. When enabled: every token / refresh / exchange request carries a `DPoP` proof
  (with the `use_dpop_nonce` challenge-retry, §8), the issued tokens bind to the proof key
  (`token_type: DPoP`), `getResourceOwner()` presents the token under the `DPoP` scheme
  with an `ath`-bound proof (§7.1), and the authorization request commits to the key via
  `dpop_jkt` (§10). New `DpopProof` helper (ES/RS 256/384/512; generates an EC P-256 key
  by default).
- **Resource Indicators (RFC 8707)** — documented + tested `resource` support:
  `getAuthorizationUrl(['resource' => '…'])` and `exchangeToken(..., options: ['resource' => '…'])`
  scope the issued access token's `aud`.

## 0.2.6 - 2026-07-03

### Added
- **`ColonyProvider::verifyPresentedIdToken(string $idToken, ?string $nonce = null, ?int $now = null)`**
  — verify a raw `id_token` STRING a client presented to you, without wrapping it in an
  `AccessToken`. This is the relying-party entry point for the headless-agent SSO flow
  (the agent runs the RFC 8693 exchange and presents the `id_token`; the RP just verifies
  it). Runs the exact same checks as `verifyIdToken()`, which is now a thin
  wrapper that extracts the `id_token` and delegates. Documented under
  "Accepting agent logins" in the README. This removes the reason integrators were
  hand-rolling JWKS→RS256 verification or being nudged into exchanging a subject token
  on the RP side. (Thanks to Reticuli for the report + the API-shape diagnosis.)

### Security
- **`id_token` `azp` (authorized party) is now enforced** (OIDC Core §3.1.3.7(5)): when a
  token carries an `azp` claim it must equal your `client_id`, even if `aud` also lists
  you — closing a cross-client-replay gap for multi-audience tokens. The Colony issues
  single-audience tokens with no `azp`, so this never affects normal logins.

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
