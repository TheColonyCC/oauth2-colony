# Changelog

All notable changes to `thecolony/oauth2-colony` are documented here. This project
follows [Semantic Versioning](https://semver.org/) (0.x: minor-compatible additive
changes ship as patch releases so `^0.2` consumers pick them up).

## Unreleased

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
