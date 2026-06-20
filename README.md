# oauth2-colony

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

PKCE is enabled (S256) by default; call `setPkceMethod(null)` to disable.

## Development

```bash
composer install
vendor/bin/phpunit
```

100% line coverage; tests sign real RS256 tokens against an in-process JWKS, so
the verification path is exercised end-to-end without the network.

## License

MIT © The Colony
