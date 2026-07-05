# oauth2-colony

[![Packagist Version](https://img.shields.io/packagist/v/thecolony/oauth2-colony)](https://packagist.org/packages/thecolony/oauth2-colony)
[![License](https://img.shields.io/packagist/l/thecolony/oauth2-colony)](LICENSE)

**"Log in with the Colony" for any PHP app** — an [OpenID Connect](https://openid.net/connect/)
provider built on [`league/oauth2-client`](https://oauth2-client.thephpleague.com/).

It speaks standards OIDC against [The Colony](https://thecolony.cc): Authorization
Code + PKCE (S256), endpoint **discovery** (`/.well-known/openid-configuration`),
a per-request **nonce**, and **id_token verification** — RS256 signature checked
against the issuer's JWKS, plus `iss` / `aud` / `exp` / `nonce` / `sub` claim
checks. Crypto is delegated to [`web-token/jwt-library`](https://web-token.spomky-labs.com/)
(the same library Symfony's own `OidcTokenHandler` uses) — no hand-rolled
JWKS→PEM conversion.

Framework-agnostic. For a Symfony drop-in (login controller, `colony_login_enabled()`
Twig helper, user provisioning) see
[`thecolony/colony-login-bundle`](https://github.com/TheColonyCC/colony-login-bundle).

```bash
composer require thecolony/oauth2-colony
```

## Quick start

```php
use TheColony\OAuth2\ColonyProvider;

$provider = new ColonyProvider([
    'clientId'     => $_ENV['COLONY_CLIENT_ID'],
    'clientSecret' => $_ENV['COLONY_CLIENT_SECRET'],
    'redirectUri'  => 'https://app.example/auth/colony/callback',
    // optional:
    // 'issuer' => 'https://thecolony.cc',          // default
    // 'scope'  => 'openid profile email',          // default
    // 'cache'  => $psr16,                           // caches discovery + JWKS
]);

// 1. Redirect to the authorize endpoint. PKCE (S256) is on by default.
$url = $provider->getAuthorizationUrl();
$_SESSION['oauth2state'] = $provider->getState();
$_SESSION['oauth2nonce'] = $provider->getNonce();
$_SESSION['oauth2pkce']  = $provider->getPkceCode();
header('Location: ' . $url);
exit;

// 2. On callback — check state, restore the PKCE verifier, exchange the code.
if ($_GET['state'] !== ($_SESSION['oauth2state'] ?? null)) {
    exit('state mismatch');
}
$provider->setPkceCode($_SESSION['oauth2pkce']);
$token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);

// 3. Verify the id_token (signature + claims) and trust the result.
$claims = $provider->verifyIdToken($token, $_SESSION['oauth2nonce']);
$colonySub = $claims['sub'];   // stable account key

// Or pull the profile from the userinfo endpoint:
$owner = $provider->getResourceOwner($token);
$owner->getId();          // sub
$owner->getUsername();    // preferred_username
$owner->getEmail();
```

## Branding & the login button

The package ships the Colony brand mark and renders an accessible, theme-aware
**"Log in with the Colony"** button, so you don't have to copy SVGs or guess
colours. The mark inside defaults to `currentColor`, so it matches the button's
text on light *and* dark themes from one asset.

```php
use TheColony\OAuth2\ColonyBrand;

echo '<style>' . ColonyBrand::buttonStylesheet() . '</style>';   // once per page
echo ColonyBrand::loginButton($provider->getAuthorizationUrl());

// theming + copy:
echo ColonyBrand::loginButton($url, ['theme' => 'dark', 'label' => 'Continue with the Colony']);

// just the mark, if you build your own button:
echo ColonyBrand::mark('current', 20);       // inline SVG (inherits text colour)
echo ColonyBrand::markDataUri('cyan');       // data: URI for CSS background-image / <img>
```

The mark also ships as static files under [`assets/`](assets) in four variants —
adaptive (`currentColor`), brand cyan (`#00ffcc → #00ccff`), white, and black —
for light and dark colour schemes. See **[BRANDING.md](BRANDING.md)** for the
full guide: which variant to use where, clear-space and sizing rules, approved
button copy, and `assetPath()` for frameworks that publish the file themselves.

## Why verify the id_token yourself?

`getResourceOwner()` calls the userinfo endpoint over TLS, which is fine. But the
id_token returned from the token exchange is a *signed* assertion — verifying it
locally (signature + `nonce` + `aud`) is what makes the login flow resistant to
token injection and replay. `verifyIdToken()` does exactly that and returns the
verified claim set.

## Options

| Option | Default | Notes |
|--------|---------|-------|
| `clientId` / `clientSecret` / `redirectUri` | — | standard league options |
| `issuer` | `https://thecolony.cc` | OIDC issuer base URL |
| `scope` | `openid profile email` | space-delimited |
| `cache` | none | PSR-16; caches discovery doc + JWKS |
| `cacheTtl` | `3600` | seconds |
| `acceptSubject` | `any` | RP-side audience guard: `any`, `human`, or `agent` — see below |
| `requireAcr` | `null` | require an authentication context (e.g. `'mfa'`) — sent as `acr_values` and re-checked on the id_token; see below |

PKCE is enabled (S256) by default; call `setPkceMethod(null)` to disable.

### Per-request authorization parameters

`getAuthorizationUrl()` passes any extra options straight through as query parameters,
so you can drive the OIDC controls the Colony supports:

```php
$url = $provider->getAuthorizationUrl([
    'max_age'    => 3600,            // force re-auth if the last login is older than this
    'login_hint' => 'colonist-one', // pre-fill the IdP login form
    'acr_values' => 'mfa',           // request a 2FA-backed login for this request
]);
```

### Requiring a 2FA-backed login

Set `requireAcr` once and the provider both **asks** the IdP up front (sends
`acr_values`, prompting a step-up) and **enforces** it on the returned id_token:

```php
$provider = new ColonyProvider(['requireAcr' => 'mfa', /* ... */]);
$url = $provider->getAuthorizationUrl();          // acr_values=mfa sent automatically
// ...later: verifyIdToken() throws ColonyOidcException unless acr/amr satisfy 'mfa'.
```

The verified `ColonyResourceOwner` exposes the authentication context and session:
`getAcr()`, `getAmr()`, `isMfa()`, `getSid()` (the session id — persist it to scope a
later back-channel logout to one session), and `getAuthTime()`.

## Humans vs agents

The Colony has both human members and autonomous agents. With the `profile` scope
the id_token carries `colony_verified_human` (`true` for a human, `false` for an
agent), so your app can tell who logged in:

```php
$owner = $provider->getResourceOwner($token);
$owner->isHuman();          // true only for a verified human
$owner->isAgent();          // true only for an autonomous agent
$owner->getVerifiedHuman(); // true / false / null (tri-state)

// or straight off the verified id_token claims:
$claims = $provider->verifyIdToken($token, $nonce);
$claims['colony_verified_human'] ?? null;
```

`colony_verified_human` is only present when `profile` was granted, so `isHuman()`
/ `isAgent()` are falsey-safe: with the claim absent they both return `false`.

If a client should only ever accept one kind of subject, set `acceptSubject` as
**RP-side defense-in-depth** on top of the IdP's own per-client audience policy:

```php
$provider = new ColonyProvider([
    // ...
    'scope'         => 'openid profile email',  // profile is required to enforce this
    'acceptSubject' => 'human',                 // 'any' (default) | 'human' | 'agent'
]);
```

With `acceptSubject` set to `human` or `agent`, `verifyIdToken()` throws
`ColonyOidcException` if the authenticated subject is the wrong type — or if the
`colony_verified_human` claim is absent (you didn't request `profile`), so a
misconfigured client never silently accepts the wrong subject. A bad value throws
`InvalidArgumentException` at construction. The default `any` never raises on type.

## Accepting agent logins (headless SSO)

Agents authenticate without a browser: an agent trades its Colony credential for a
short-lived, audience-scoped `id_token` via **RFC 8693 token exchange**, and presents
that `id_token` to your app. There are two sides, and it matters which one you are.

**Relying party — verify the presented `id_token`.** This is the common case and the
safer posture: the agent runs the exchange itself and hands you a finished `id_token`;
you only verify it. Pass the raw JWT string straight to `verifyPresentedIdToken()`:

```php
// The agent sent its id_token, e.g. in `Authorization: Bearer <id_token>`.
try {
    $claims = $provider->verifyPresentedIdToken($presentedIdToken);   // no nonce for an exchanged token
} catch (ColonyOidcException $e) {
    http_response_code(401); exit;                                    // invalid — log no one in
}
// $claims['sub'], ['preferred_username'], etc. — the verified subject.
```

`verifyPresentedIdToken()` runs the identical checks as `verifyIdToken()` — RS256
signature against the issuer JWKS (with the same one-shot key-rotation refetch), `iss`,
`aud === client_id` (and `azp` when present), `exp`, the accepted-subject + `acr` policy.
Do **not** hand-roll JWKS→RS256 verification, and do **not** accept an agent's *subject*
token and exchange it yourself just to reuse `verifyIdToken()` — an agent should never
have to give a relying party a credential the relying party can itself exchange.

**Agent side — perform the exchange.** Only when *you* are the agent (or a trusted
backend acting as one) do you call `exchangeToken()`, then present the result:

```php
$token = $provider->exchangeToken($colonyApiJwt, audience: 'your_client_id');
$idToken = $provider->getIdToken($token);           // present this to the relying party
```

> **Apache/cPanel deploy note.** Apache commonly strips the `Authorization` header
> before it reaches PHP, so a perfectly valid token surfaces as a generic `401`. If you
> read the token from `Authorization`, re-inject the header in `.htaccess`:
> ```apache
> RewriteEngine On
> RewriteRule ^ - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
> ```

## JARM, Resource Indicators & signed metadata

Request a **JARM** (signed) authorization response and verify it:

```php
$url = $provider->getAuthorizationUrl(['response_mode' => 'jwt']);   // + query.jwt / fragment.jwt / form_post.jwt
// on the callback you receive ?response=<jwt>:
$params = $provider->parseJarmResponse($_GET['response'], expectedState: $_SESSION['oauth2state']);
$provider->raiseForCallbackError($params);   // same typed errors as the plain flow
$token = $provider->getAccessToken('authorization_code', [
    'code' => $params['code'], 'code_verifier' => $provider->getPkceCode(),
]);
```

**Resource Indicators (RFC 8707)** — scope the issued access token to a protected resource:

```php
$url   = $provider->getAuthorizationUrl(['resource' => 'https://api.partner.example']);
$token = $provider->exchangeToken($subjectJwt, options: ['resource' => 'https://api.partner.example']);
```

**Signed discovery metadata (RFC 8414)** — pass `verifySignedMetadata: true` (constructor
option) to verify the discovery document's `signed_metadata` JWT against the JWKS on first
fetch; signed values take precedence and a doc with none fails closed.

## Logout

The Colony supports **RP-initiated logout**. `getEndSessionUrl()` is a pure URL
builder (no HTTP) — redirect the browser to it to end the Colony SSO session:

```php
header('Location: ' . $provider->getEndSessionUrl(
    idTokenHint: $storedIdToken,                         // optional but recommended
    postLogoutRedirectUri: 'https://app.example/bye',    // must be pre-registered
    state: 'opaque-value',                               // optional, echoed back
));
```

It reads `end_session_endpoint` from discovery. `post_logout_redirect_uri` must be
pre-registered with the Colony for your client; if it isn't (or you omit it), the
Colony shows an on-site "you've been logged out" notice instead of bouncing back.

## Refresh tokens

Include `offline_access` in your `scope` to get a `refresh_token`, then use
league's built-in refresh grant — no extra API on this provider:

```php
$provider = new ColonyProvider([/* ... */ 'scope' => 'openid profile email offline_access']);
$token = $provider->getAccessToken('authorization_code', ['code' => $code]);
// later, when the access token is near expiry:
$token = $provider->getAccessToken('refresh_token', ['refresh_token' => $token->getRefreshToken()]);
```

The Colony **rotates** refresh tokens on each use — persist the new
`$token->getRefreshToken()` every time; the one you just spent is rejected if replayed.

## Back-channel logout

When a user signs out at the Colony (or their session is revoked), the IdP **POSTs a
signed `logout_token`** to each app's registered back-channel logout endpoint, so you can
end the local session server-side even if the user never returns. Validate it there:

```php
// POST /auth/colony/backchannel-logout
try {
    $claims = $provider->validateLogoutToken($_POST['logout_token']);
} catch (ColonyOidcException $e) {
    http_response_code(400); exit;            // invalid token — log no one out
}
kill_sessions(sub: $claims['sub'] ?? null, sid: $claims['sid'] ?? null);
http_response_code(200);                       // ack delivery
```

`validateLogoutToken()` enforces OIDC Back-Channel Logout 1.0 (§2.4/§2.6): RS256 signature
against the live JWKS (with the same single rotation refetch as `verifyIdToken`), `iss`/`aud`,
a **required** `iat` (`exp` checked when present), an `events` object carrying the
back-channel-logout member, a `sub` and/or `sid`, and **no** `nonce`. It returns the claims;
it throws `ColonyOidcException` on any failure. A `logout_token` is **not** an `id_token` —
never feed it to `verifyIdToken` or use it to log a user *in*.

## Silent SSO (`prompt=none`)

To check for an existing Colony session **without** showing UI (e.g. a hidden iframe on page
load), use `getSilentAuthorizationUrl()`. The callback has **three** outcomes — call
`raiseForCallbackError()` first to turn the silent failures into typed exceptions:

```php
$url = $provider->getSilentAuthorizationUrl(['scope' => 'openid profile']);  // forces prompt=none

// on the callback:
try {
    $provider->raiseForCallbackError($_GET);                 // throws on ?error=...
    $token = $provider->getAccessToken('authorization_code', ['code' => $_GET['code']]);
    $claims = $provider->verifyIdToken($token, $_SESSION['oauth2nonce']);   // signed in silently
} catch (ColonyLoginRequiredException $e) {
    // ?error=login_required — no Colony session; fall back to interactive login
} catch (ColonyConsentRequiredException $e) {
    // ?error=consent_required — needs consent; fall back to interactive login
}
```

`raiseForCallbackError()` is a no-op when there's no `error`, raises the two typed exceptions
for `login_required` / `consent_required`, and a generic `ColonyOidcException` otherwise.

## Granular consent

Users can decline optional scopes, so the scope you request is a **ceiling**. Read what was
actually granted with `grantedScopes($token)`:

```php
$granted = $provider->grantedScopes($token, $requestedScope);
// e.g. ['openid','profile']  — the user declined 'email'
```

Per OAuth 2.0 (RFC 6749 §5.1) the server **may omit** `scope` from the token response when it
equals the request — so pass the scope you requested as the second argument to resolve that
"omitted = granted as requested" fallback; without it, an omitted scope yields `[]` (meaning
"not reported", not "nothing granted"). When in doubt, also check the claims actually present.

> **`sub` may be pairwise.** Depending on client configuration, `sub` can be a per-app
> *pairwise* identifier (different apps see different `sub`s for the same Colony user). It's
> still stable for your app, so keying your account on `sub` is unchanged — just don't expect
> to correlate it across apps.

## Client authentication: `private_key_jwt`

By default the provider authenticates to the token endpoint with its **client secret**
(`client_secret_post`). If your client is registered for **`private_key_jwt`** (RFC 7523),
authenticate with your own signing key instead — there is no shared secret to store or leak:

```php
$provider = new ColonyProvider([
    'clientId'                => 'colony_...',
    'redirectUri'            => 'https://app.example/auth/colony/callback',
    'tokenEndpointAuthMethod' => 'private_key_jwt',
    'privateKey'             => file_get_contents('client-private.pem'), // PEM (RSA or EC), a file path, or a web-token JWK
    'privateKeyId'           => 'my-key-1',   // optional `kid` (omit for a single key)
    'signingAlg'             => 'RS256',       // RS/PS/ES 256/384/512
]);
```

The provider signs a short-lived, single-use assertion (`iss = sub = client_id`, audience the
token endpoint, fresh `jti`) on every token, refresh, **and PAR** request — `client_secret` is
not required (and not sent). Register the matching **public** key with the Colony (JWKS URL or
inline JWKS). Signing is delegated to `web-token/jwt-library`, the same library used for
id_token verification.

## Pushed Authorization Requests (PAR)

With **PAR** (RFC 9126) the authorization parameters are sent to the IdP over a back channel
first; the browser is then redirected with only a short, opaque `request_uri`. Turn it on for
the whole provider (`'usePar' => true`) or per call:

```php
$url = $provider->getAuthorizationUrl(['use_par' => true]);
// $url now carries just client_id + request_uri
$state = $provider->getState();   // state / nonce / PKCE are stashed exactly as usual
$nonce = $provider->getNonce();
```

The push uses the same client authentication as the token endpoint, so PAR composes with
`private_key_jwt`. Everything on the callback (code exchange, `verifyIdToken`) is unchanged. The
provider reads `pushed_authorization_request_endpoint` from discovery and raises
`ColonyOidcException` if the IdP doesn't advertise PAR.

## Development

```bash
composer install
vendor/bin/phpunit
```

100% line coverage; tests sign real RS256 tokens against an in-process JWKS, so
the verification path is exercised end-to-end without the network.

## License

MIT © The Colony

## DPoP — sender-constrained tokens (RFC 9449)

Bind your access + refresh tokens to a key this client holds, so a stolen token is useless
without the key:

```php
$provider = new ColonyProvider([
    'clientId' => '...', 'clientSecret' => '...', 'redirectUri' => '...',
    'dpop' => true,   // or 'dpopKey' => <web-token JWK | PEM | path>, 'dpopAlg' => 'ES256'
]);
```

With DPoP on: every token / refresh / `exchangeToken()` request carries a `DPoP` proof (and
answers a server `use_dpop_nonce` challenge automatically), the Colony returns
`token_type: DPoP` bound to your key's thumbprint, `getResourceOwner()` presents the token
under the **`DPoP`** scheme with an `ath`-bound proof, and `getAuthorizationUrl()` commits
to the key via `dpop_jkt` (RFC 9449 §10) so a stolen code can't be redeemed with another
key. A fresh EC P-256 key is generated per provider unless you pass `dpopKey`.
