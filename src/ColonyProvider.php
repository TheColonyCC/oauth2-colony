<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;
use TheColony\OAuth2\Exception\ColonyConsentRequiredException;
use TheColony\OAuth2\Exception\ColonyLoginRequiredException;
use TheColony\OAuth2\Exception\ColonyOidcException;

/**
 * "Log in with the Colony" — an OpenID Connect provider on top of
 * league/oauth2-client.
 *
 * Authorization Code + PKCE is handled by league (call
 * {@see setPkceMethod()} with {@see AbstractProvider::PKCE_METHOD_S256}).
 * This class adds the OIDC parts: endpoint discovery, a per-request `nonce`,
 * and id_token signature/claim verification (delegated to {@see IdTokenVerifier},
 * which uses web-token/jwt-library).
 *
 * Recognised constructor options (in addition to league's clientId /
 * clientSecret / redirectUri): `issuer` (Colony base URL, default
 * https://thecolony.cc), `scope` (space-delimited, default "openid profile
 * email"), and optional `cache` (PSR-16) + `cacheTtl` for discovery/JWKS.
 *
 * Partner-auth options: `tokenEndpointAuthMethod` — `client_secret_post`
 * (default) or `private_key_jwt` (RFC 7523); for the latter pass `privateKey`
 * (a PEM string, a PEM file path, or a web-token JWK), an optional
 * `privateKeyId` (`kid`), and `signingAlg` (RS/PS/ES 256/384/512, default
 * RS256). `usePar` turns on Pushed Authorization Requests (RFC 9126) for every
 * authorization URL (or pass `['use_par' => true]` per call).
 */
final class ColonyProvider extends AbstractProvider
{
    protected string $issuer = 'https://thecolony.cc';
    protected ?string $scope = null;
    protected ?CacheInterface $cache = null;
    protected int $cacheTtl = 3600;
    /** PKCE is on by default — "Log in with the Colony" should always use it. */
    protected ?string $pkceMethod = self::PKCE_METHOD_S256;
    /** RP-side audience restriction: "any" (default), "human", or "agent". */
    protected string $acceptSubject = 'any';

    /**
     * When set (e.g. `'mfa'`), require this Authentication Context Class. The provider
     * sends it as `acr_values` on the authorization request — so the IdP enforces it up
     * front (prompting a 2FA step-up) — and re-checks the returned id_token's `acr`/`amr`
     * in {@see verifyIdToken} as defence in depth. Null (default) = no requirement.
     */
    protected ?string $requireAcr = null;
    /** Token/PAR-endpoint client auth: 'client_secret_post' (default) or 'private_key_jwt'. */
    protected string $tokenEndpointAuthMethod = 'client_secret_post';
    /** For private_key_jwt: a PEM string, a path to a PEM file, or a web-token JWK. */
    protected mixed $privateKey = null;
    /** For private_key_jwt: optional `kid` header (omit for a single key). */
    protected ?string $privateKeyId = null;
    /** For private_key_jwt: the assertion signing algorithm (RS/PS/ES 256/384/512). */
    protected string $signingAlg = 'RS256';
    /** Push the authorization request server-side (RFC 9126) for every authorization URL. */
    protected bool $usePar = false;

    /**
     * When true, the discovery document's `signed_metadata` JWT (RFC 8414 §2.1/§3.2) is
     * verified against the published JWKS on first fetch and its signed claims take
     * precedence over the plain JSON — so a doc fetched over a hostile network is proven
     * un-tampered. A discovery doc with no `signed_metadata` then throws (fail closed).
     */
    protected bool $verifySignedMetadata = false;

    /** Client auth methods this provider implements at the token / PAR endpoints. */
    private const TOKEN_AUTH_METHODS = ['client_secret_post', 'private_key_jwt'];
    /** RFC 7521 §4.2 client-assertion type for private_key_jwt. */
    private const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    /** Asymmetric algorithms the Colony's token/PAR verifier accepts (RFC 7523). */
    private const CLIENT_ASSERTION_ALGS = [
        'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512',
    ];
    /** Each assertion is single-use + short-lived; the IdP caps the accepted lifetime at 5 min. */
    private const ASSERTION_LIFETIME = 60;
    /** RFC 8693 OAuth 2.0 Token Exchange grant. */
    private const GRANT_TOKEN_EXCHANGE = 'urn:ietf:params:oauth:grant-type:token-exchange';
    /** RFC 8693 token-type URN for a subject token that is an access token / bearer JWT. */
    private const TOKEN_TYPE_ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';

    private ?string $nonce = null;
    private IdTokenVerifier $idTokenVerifier;
    /** @var array<string,mixed>|null */
    private ?array $discoveryMemo = null;

    /**
     * @param array<string,mixed> $options
     * @param array<string,mixed> $collaborators
     */
    public function __construct(array $options = [], array $collaborators = [])
    {
        parent::__construct($options, $collaborators);
        $this->issuer = rtrim($this->issuer, '/');
        if (!in_array($this->acceptSubject, ['any', 'human', 'agent'], true)) {
            throw new \InvalidArgumentException("acceptSubject must be 'any', 'human', or 'agent'");
        }
        if (!in_array($this->tokenEndpointAuthMethod, self::TOKEN_AUTH_METHODS, true)) {
            throw new \InvalidArgumentException(
                'tokenEndpointAuthMethod must be one of: ' . implode(', ', self::TOKEN_AUTH_METHODS),
            );
        }
        if ($this->tokenEndpointAuthMethod === 'private_key_jwt') {
            if (empty($this->privateKey)) {
                throw new \InvalidArgumentException(
                    "privateKey is required for tokenEndpointAuthMethod='private_key_jwt'",
                );
            }
            if (!in_array($this->signingAlg, self::CLIENT_ASSERTION_ALGS, true)) {
                throw new \InvalidArgumentException(
                    'signingAlg must be one of: ' . implode(', ', self::CLIENT_ASSERTION_ALGS),
                );
            }
        }
        // Note: client_secret_post is NOT required to have a secret at construction.
        // The provider is commonly a long-lived DI service (e.g. via colony-login-bundle)
        // that's instantiated while the login is still dormant/unconfigured; like league's
        // default it constructs fine and only an actual token request needs the secret.
        $this->idTokenVerifier = $collaborators['idTokenVerifier'] ?? new IdTokenVerifier();
    }

    // -- league endpoints (resolved from OIDC discovery) ----------------------

    public function getBaseAuthorizationUrl(): string
    {
        return $this->endpoint('authorization_endpoint', '/oauth/authorize');
    }

    public function getBaseAccessTokenUrl(array $params): string
    {
        return $this->endpoint('token_endpoint', '/oauth/token');
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return $this->endpoint('userinfo_endpoint', '/oauth/userinfo');
    }

    protected function getDefaultScopes(): array
    {
        $scope = trim((string) $this->scope);
        if ($scope === '') {
            return ['openid', 'profile', 'email'];
        }

        return preg_split('/\s+/', $scope) ?: ['openid'];
    }

    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if ($response->getStatusCode() < 400 && !(is_array($data) && isset($data['error']))) {
            return;
        }
        $message = is_array($data)
            ? (string) ($data['error_description'] ?? $data['error'] ?? $response->getReasonPhrase())
            : $response->getReasonPhrase();
        throw new IdentityProviderException($message, $response->getStatusCode(), $data);
    }

    /** @param array<string,mixed> $response */
    protected function createResourceOwner(array $response, AccessToken $token): ColonyResourceOwner
    {
        return new ColonyResourceOwner($response);
    }

    // -- OIDC: nonce ----------------------------------------------------------

    protected function getAuthorizationParameters(array $options): array
    {
        $params = parent::getAuthorizationParameters($options);
        $this->nonce = $options['nonce'] ?? $this->getRandomState();
        $params['nonce'] = $this->nonce;
        // Auto-send acr_values from a configured requireAcr so the IdP enforces the
        // authentication context up front (e.g. a 2FA step-up). An explicit
        // ['acr_values' => ...] passed to getAuthorizationUrl() wins (it's already in
        // $params via the parent merge). max_age / login_hint / prompt similarly flow
        // through $options untouched.
        if ($this->requireAcr !== null && !isset($params['acr_values'])) {
            $params['acr_values'] = $this->requireAcr;
        }

        return $params;
    }

    /** The nonce minted for the last authorization URL — persist it to verify the id_token. */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * Build a **silent SSO** authorization URL (`prompt=none`): the IdP shows no UI.
     *
     * Use it (typically in a hidden iframe) to re-authenticate a user who already has a
     * Colony session without an interactive redirect. The callback then yields one of three
     * outcomes — `?code=...` on success, or `?error=login_required` / `?error=consent_required`
     * on failure — which {@see raiseForCallbackError()} turns into typed exceptions. Accepts
     * the same `$options` as `getAuthorizationUrl()`; any `prompt` you pass is forced to `none`.
     *
     * @param array<string,mixed> $options
     */
    public function getSilentAuthorizationUrl(array $options = []): string
    {
        $options['prompt'] = 'none';

        return $this->getAuthorizationUrl($options);
    }

    /**
     * Set the PKCE method (defaults to S256). Pass null to disable PKCE.
     * Provided for parity with newer league/oauth2-client releases that ship a
     * setter; this works on the 2.7+ baseline too.
     */
    public function setPkceMethod(?string $method): static
    {
        $this->pkceMethod = $method;

        return $this;
    }

    protected function getPkceMethod(): ?string
    {
        return $this->pkceMethod;
    }

    // -- OIDC: id_token -------------------------------------------------------

    public function getIdToken(AccessToken $token): ?string
    {
        $idToken = $token->getValues()['id_token'] ?? null;

        return is_string($idToken) ? $idToken : null;
    }

    /**
     * RFC 8693 OAuth 2.0 Token Exchange — the agent-native path: trade a subject
     * token (e.g. an agent's Colony API JWT) for a fresh, audience-scoped id_token,
     * with no browser, redirect, authorization code or nonce.
     *
     * The returned {@see AccessToken} carries the issued `id_token` in its values,
     * so {@see getIdToken()} and {@see verifyIdToken()} (call it with a `null` nonce —
     * exchanged tokens carry none) work on it directly. Client authentication
     * (client_secret_post / private_key_jwt) is attached when configured, the same
     * as the authorization_code path; the subject token identifies the acting party.
     *
     * @param string              $subjectToken the token identifying the acting party (the Colony API JWT)
     * @param string|null         $audience     the target audience for the issued token; defaults to this client's id
     * @param string              $scope        requested scope (defaults to `openid profile`)
     * @param array<string,mixed> $options      extra token-request params (e.g. `subject_token_type`, `resource`, `requested_token_type`)
     *
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException on an OAuth error response
     * @throws ColonyOidcException on a malformed (non-object) token response
     */
    public function exchangeToken(string $subjectToken, ?string $audience = null, string $scope = 'openid profile', array $options = []): AccessToken
    {
        $params = array_filter([
            'grant_type' => self::GRANT_TOKEN_EXCHANGE,
            'subject_token' => $subjectToken,
            'subject_token_type' => self::TOKEN_TYPE_ACCESS_TOKEN,
            'audience' => $audience ?? (string) $this->clientId,
            'scope' => $scope,
        ], static fn ($v): bool => $v !== null && $v !== '');
        $params = array_merge($params, $options);

        // getAccessTokenRequest() (overridden here) attaches client auth and posts
        // to the discovered token endpoint; getParsedResponse() runs checkResponse()
        // so OAuth error bodies surface as IdentityProviderException, as elsewhere.
        $response = $this->getParsedResponse($this->getAccessTokenRequest($params));
        if (!is_array($response)) {
            throw new ColonyOidcException('unexpected token-exchange response (not a JSON object)');
        }

        return new AccessToken($response);
    }

    /**
     * Verify the id_token's signature against the issuer JWKS and its core
     * claims, returning the claim set.
     *
     * Pass the `nonce` you bound to the authorization request; pass `null` to skip
     * the nonce check (e.g. for an id_token obtained via {@see exchangeToken()},
     * which has no nonce and no redirect/replay vector).
     *
     * When a cache is configured, the JWKS is re-fetched once if verification
     * fails against the cached set — this transparently rides out a signing-key
     * rotation at the issuer without waiting for the cache TTL to lapse.
     *
     * @return array<string,mixed>
     */
    public function verifyIdToken(AccessToken $token, ?string $expectedNonce = null, ?int $now = null): array
    {
        $idToken = $this->getIdToken($token);
        if ($idToken === null) {
            throw new ColonyOidcException('token response did not include an id_token');
        }

        return $this->verifyPresentedIdToken($idToken, $expectedNonce, $now);
    }

    /**
     * Verify a raw id_token STRING that a client presented to THIS relying party,
     * returning the verified claim set.
     *
     * This is the RP-side entry point for the headless-agent SSO flow: the agent runs
     * the RFC 8693 token exchange itself (see {@see exchangeToken()}) and presents the
     * resulting id_token; the relying party only has to verify it. Prefer this over
     * exchanging a subject token the agent handed you — an agent should never have to
     * give a relying party a credential the relying party can itself exchange. See the
     * "Accepting agent logins" section of the README.
     *
     * Runs exactly the same checks as {@see verifyIdToken()} — RS256 signature against
     * the issuer JWKS, `iss`, `aud === client_id` (and `azp` when present), `exp`, the
     * optional `nonce`, and the accepted-subject + `acr` policy — with the same
     * transparent one-shot JWKS re-fetch on a signing-key rotation. Pass the bound
     * `nonce` for the front-channel code flow; pass `null` for an exchanged/presented
     * token (it carries no nonce and no redirect/replay vector).
     *
     * @return array<string,mixed>
     */
    public function verifyPresentedIdToken(string $idToken, ?string $expectedNonce = null, ?int $now = null): array
    {
        $disc = $this->discovery();
        $issuer = (string) ($disc['issuer'] ?? $this->issuer);
        $jwksUri = (string) ($disc['jwks_uri'] ?? $this->issuer . '/.well-known/jwks.json');
        $cacheKey = 'colony_oidc_jwks_' . sha1($jwksUri);

        try {
            $claims = $this->idTokenVerifier->verify(
                $idToken,
                $this->cached($cacheKey, fn () => $this->httpGet($jwksUri)),
                $issuer,
                (string) $this->clientId,
                $expectedNonce,
                $now,
            );
        } catch (ColonyOidcException $e) {
            // Only retry the signature step, and only when a cache could have
            // served a stale key set (uncached fetches are already fresh).
            if ($this->cache === null || !str_contains($e->getMessage(), 'signature')) {
                throw $e;
            }
            $fresh = $this->httpGet($jwksUri);
            $this->cache->set($cacheKey, $fresh, $this->cacheTtl);

            $claims = $this->idTokenVerifier->verify($idToken, $fresh, $issuer, (string) $this->clientId, $expectedNonce, $now);
        }

        $this->assertSubjectAccepted($claims);
        $this->assertAcrSatisfied($claims);

        return $claims;
    }

    /**
     * Verify + unpack a JARM (JWT Secured Authorization Response) `response` parameter.
     *
     * When you request `response_mode=jwt` (or query.jwt / fragment.jwt / form_post.jwt) —
     * pass `['response_mode' => 'jwt']` to {@see getAuthorizationUrl()} — the Colony returns
     * the whole authorization response as a single signed JWT in the `response` parameter.
     * Pass that JWT here: its RS256 signature is verified against the issuer JWKS and its
     * `iss` / `aud` / `exp` claims are checked (the `iss` **claim** is JARM's mix-up defence,
     * replacing the RFC 9207 `iss` *parameter*, which JARM omits). Returns the inner
     * authorization-response params (`code`+`state` on success, or `error`+`error_description`
     * on failure) with the JARM envelope stripped — feed them to {@see raiseForCallbackError()}
     * and then the normal `getAccessToken('authorization_code', ...)` flow.
     *
     * Pass `$expectedState` (the value from {@see getState()}) to have `state` checked here.
     * Uses the same transparent one-shot JWKS re-fetch on a signing-key rotation as
     * {@see verifyIdToken()}.
     *
     * @return array<string,mixed>
     */
    public function parseJarmResponse(string $responseJwt, ?string $expectedState = null, ?int $now = null): array
    {
        $disc = $this->discovery();
        $issuer = (string) ($disc['issuer'] ?? $this->issuer);
        $jwksUri = (string) ($disc['jwks_uri'] ?? $this->issuer . '/.well-known/jwks.json');
        $cacheKey = 'colony_oidc_jwks_' . sha1($jwksUri);

        try {
            return $this->idTokenVerifier->verifyJarm(
                $responseJwt,
                $this->cached($cacheKey, fn () => $this->httpGet($jwksUri)),
                $issuer,
                (string) $this->clientId,
                $expectedState,
                $now,
            );
        } catch (ColonyOidcException $e) {
            if ($this->cache === null || !str_contains($e->getMessage(), 'signature')) {
                throw $e;
            }
            $fresh = $this->httpGet($jwksUri);
            $this->cache->set($cacheKey, $fresh, $this->cacheTtl);

            return $this->idTokenVerifier->verifyJarm(
                $responseJwt, $fresh, $issuer, (string) $this->clientId, $expectedState, $now,
            );
        }
    }

    /**
     * Validate a back-channel `logout_token` (OIDC Back-Channel Logout 1.0).
     *
     * Call this from your registered back-channel logout endpoint with the `logout_token`
     * the Colony POSTs there. Returns the validated claims (carrying a `sub` and/or `sid`)
     * so you can terminate that subject's / session's local session; throws
     * {@see ColonyOidcException} on any failure. Verification (signature against the live
     * JWKS, with the same single rotation refetch as {@see verifyIdToken}; `iss` / `aud`;
     * required `iat`; `exp` when present; required `events` member; `sub`/`sid`; no `nonce`)
     * is delegated to {@see IdTokenVerifier::verifyLogoutToken()}.
     *
     * @return array<string,mixed>
     */
    public function validateLogoutToken(string $logoutToken, ?int $now = null): array
    {
        $disc = $this->discovery();
        $issuer = (string) ($disc['issuer'] ?? $this->issuer);
        $jwksUri = (string) ($disc['jwks_uri'] ?? $this->issuer . '/.well-known/jwks.json');
        $cacheKey = 'colony_oidc_jwks_' . sha1($jwksUri);

        try {
            return $this->idTokenVerifier->verifyLogoutToken(
                $logoutToken,
                $this->cached($cacheKey, fn () => $this->httpGet($jwksUri)),
                $issuer,
                (string) $this->clientId,
                $now,
            );
        } catch (ColonyOidcException $e) {
            if ($this->cache === null || !str_contains($e->getMessage(), 'signature')) {
                throw $e;
            }
            $fresh = $this->httpGet($jwksUri);
            $this->cache->set($cacheKey, $fresh, $this->cacheTtl);

            return $this->idTokenVerifier->verifyLogoutToken($logoutToken, $fresh, $issuer, (string) $this->clientId, $now);
        }
    }

    /**
     * OIDC Front-Channel Logout 1.0 receiver: validate the `iss` + `sid` query parameters
     * the Colony sends to your registered `frontchannel_logout_uri` (typically loaded in a
     * hidden iframe) when a connected user signs out, so you can clear the matching local
     * session — keyed by `sid`, which you persisted from {@see ColonyResourceOwner::getSid()}
     * at login. Unlike {@see validateLogoutToken()} (back-channel) there is no signed token to
     * verify; the front-channel notification is a bare redirect, so the only checks are that
     * the `iss` matches the configured issuer and a non-empty `sid` is present. Returns cleanly
     * when both are valid; throws {@see ColonyOidcException} otherwise.
     *
     * Example:
     * ```php
     * $provider->validateFrontChannelLogout($_GET);
     * $yourSessionStore->destroyBySid((string) $_GET['sid']);
     * ```
     *
     * @param array<string,mixed> $params the request query parameters (`$_GET`)
     * @throws ColonyOidcException if the issuer is wrong or `sid` is missing/empty
     */
    public function validateFrontChannelLogout(array $params): void
    {
        $returnedIss = $params['iss'] ?? null;
        if (!is_string($returnedIss) || $returnedIss === '') {
            throw new ColonyOidcException('front-channel logout missing iss parameter');
        }
        if ($returnedIss !== $this->issuer) {
            throw new ColonyOidcException(
                "front-channel logout issuer mismatch: expected '{$this->issuer}', got '{$returnedIss}'",
            );
        }
        $sid = $params['sid'] ?? null;
        if (!is_string($sid) || $sid === '') {
            throw new ColonyOidcException('front-channel logout missing sid parameter');
        }
    }

    /**
     * The scopes the user actually granted, parsed from the token response's `scope`.
     *
     * Under **granular consent** a user may decline optional scopes, so the requested
     * scope is a *ceiling*. Note OAuth 2.0 (RFC 6749 §5.1) lets the server **omit** `scope`
     * when it equals what was requested — so an empty result means "not reported, assume
     * the requested set", *not* "nothing granted". Pass the scope you requested as
     * `$requested` to get that fallback resolved for you.
     *
     * @param string|null $requested the scope string you requested (for the omitted-scope fallback)
     * @return list<string>
     */
    public function grantedScopes(AccessToken $token, ?string $requested = null): array
    {
        $scope = $token->getValues()['scope'] ?? null;
        if (!is_string($scope) || trim($scope) === '') {
            $scope = $requested ?? '';
        }

        return array_values(array_filter(preg_split('/\s+/', trim((string) $scope)) ?: []));
    }

    /**
     * Inspect the callback query params and raise on any OAuth `error`.
     *
     * Call this **first** on the callback, before exchanging the code. For the silent-SSO
     * (`prompt=none`) outcomes it raises the typed
     * {@see \TheColony\OAuth2\Exception\ColonyLoginRequiredException} /
     * {@see \TheColony\OAuth2\Exception\ColonyConsentRequiredException}; any other `error`
     * raises a generic {@see ColonyOidcException}. Returns cleanly when there is no `error`.
     *
     * @param array<string,mixed> $params
     */
    public function raiseForCallbackError(array $params): void
    {
        $error = $params['error'] ?? null;
        if (!is_string($error) || $error === '') {
            return;
        }
        $description = (string) ($params['error_description'] ?? '');
        $detail = $description !== '' ? "{$error}: {$description}" : $error;
        if ($error === 'login_required') {
            throw new ColonyLoginRequiredException($detail);
        }
        if ($error === 'consent_required') {
            throw new ColonyConsentRequiredException($detail);
        }
        throw new ColonyOidcException("authorization error: {$detail}");
    }

    /**
     * RFC 9207 Authorization Response Issuer (mix-up-attack defence): verify the `iss`
     * query parameter the authorization endpoint returned matches the configured issuer.
     * Call this immediately on the callback, alongside your `state` check and before
     * {@see raiseForCallbackError()} — RFC 9207 applies to success AND error responses,
     * so checking `iss` first stops an attacker's error from being mis-attributed.
     *
     * Strict by design: unlike a lenient receiver that no-ops when `iss` is absent, this
     * method *requires* `iss`. The Colony IdP always emits it (it advertises
     * `authorization_response_iss_parameter_supported`), and this is an explicit opt-in
     * method you call — so a missing `iss` is a real anomaly, not a downgrade to tolerate.
     *
     * @param array<string,mixed> $params the callback query parameters (`$_GET`)
     * @throws ColonyOidcException if `iss` is missing/empty or doesn't match the issuer
     */
    public function validateAuthorizationResponseIssuer(array $params): void
    {
        $returnedIss = $params['iss'] ?? null;
        if (!is_string($returnedIss) || $returnedIss === '') {
            throw new ColonyOidcException('authorization response missing iss parameter');
        }
        if ($returnedIss !== $this->issuer) {
            throw new ColonyOidcException(
                "authorization response issuer mismatch: expected '{$this->issuer}', got '{$returnedIss}'",
            );
        }
    }

    /**
     * Enforce the optional `acceptSubject` restriction against the verified
     * id_token claims. RP-side defense-in-depth on top of the IdP's own
     * per-client audience policy (humans only / agents only / both): when the
     * restriction is set we re-check the `colony_verified_human` claim here too,
     * so a misconfigured client never silently accepts the wrong subject type.
     *
     * @param array<string,mixed> $claims
     */
    private function assertSubjectAccepted(array $claims): void
    {
        if ($this->acceptSubject === 'any') {
            return;
        }
        if (!array_key_exists('colony_verified_human', $claims) || $claims['colony_verified_human'] === null) {
            throw new ColonyOidcException(
                "acceptSubject is restricted to '{$this->acceptSubject}' but the id_token has no "
                . "'colony_verified_human' claim — request the 'profile' scope so the subject type can be enforced",
            );
        }
        $isHuman = $claims['colony_verified_human'] === true;
        if ($this->acceptSubject === 'human' && !$isHuman) {
            throw new ColonyOidcException('this client accepts human subjects only, but an agent authenticated');
        }
        if ($this->acceptSubject === 'agent' && $isHuman) {
            throw new ColonyOidcException('this client accepts agent subjects only, but a human authenticated');
        }
    }

    /**
     * Enforce the optional `requireAcr` against the verified id_token claims. RP-side
     * defence in depth that complements sending `acr_values` on the authorization
     * request: even if the IdP somehow returned a weaker login, the RP refuses it here.
     * Satisfied when the id_token's `acr` equals the requirement OR the requirement
     * appears in `amr` (so `requireAcr='mfa'` accepts either signal).
     *
     * @param array<string,mixed> $claims
     */
    private function assertAcrSatisfied(array $claims): void
    {
        if ($this->requireAcr === null) {
            return;
        }
        $acr = isset($claims['acr']) ? (string) $claims['acr'] : null;
        $amr = is_array($claims['amr'] ?? null) ? array_map('strval', $claims['amr']) : [];
        if ($acr === $this->requireAcr || in_array($this->requireAcr, $amr, true)) {
            return;
        }
        throw new ColonyOidcException(
            "this client requires acr='{$this->requireAcr}' but the login presented "
            . "acr=" . ($acr === null ? 'null' : "'{$acr}'") . ' / amr=[' . implode(',', $amr) . ']',
        );
    }

    /**
     * The issuer's OpenID Connect discovery document (cached). Useful for
     * reading endpoints this provider doesn't wrap directly, e.g. the
     * `revocation_endpoint` (RFC 8414 / RFC 7009).
     *
     * @return array<string,mixed>
     */
    public function getOpenidConfiguration(): array
    {
        return $this->discovery();
    }

    // -- OIDC: RP-initiated logout --------------------------------------------

    /**
     * Build the RP-initiated logout (end-session) URL. No HTTP is performed —
     * redirect the user's browser here to end their Colony SSO session. The
     * `end_session_endpoint` is read from discovery (falling back to
     * `/oauth/end-session`).
     *
     * The URL always carries `client_id`; `id_token_hint`,
     * `post_logout_redirect_uri` and `state` are included only when supplied.
     * `post_logout_redirect_uri` must be **pre-registered** with the Colony for
     * this client; if it isn't (or none is given) the Colony shows an on-site
     * "you've been logged out" notice rather than bouncing the user back.
     */
    public function getEndSessionUrl(
        ?string $idTokenHint = null,
        ?string $postLogoutRedirectUri = null,
        ?string $state = null,
    ): string {
        $params = ['client_id' => (string) $this->clientId];
        if ($idTokenHint !== null && $idTokenHint !== '') {
            $params['id_token_hint'] = $idTokenHint;
        }
        if ($postLogoutRedirectUri !== null && $postLogoutRedirectUri !== '') {
            $params['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }
        if ($state !== null && $state !== '') {
            $params['state'] = $state;
        }

        return $this->endpoint('end_session_endpoint', '/oauth/end-session') . '?' . http_build_query($params);
    }

    // -- client authentication (private_key_jwt) + PAR ------------------------

    /**
     * Apply the configured client authentication to every token / refresh request
     * (league routes both through here). For `private_key_jwt` the shared secret is
     * replaced by a signed assertion; for `client_secret_post` league's body auth is
     * kept. Overriding this one method covers `getAccessToken('authorization_code')`
     * and `getAccessToken('refresh_token')` alike.
     *
     * @param array<string,mixed> $params
     */
    protected function getAccessTokenRequest(array $params): RequestInterface
    {
        return parent::getAccessTokenRequest($this->applyClientAuth($params));
    }

    /**
     * Build the authorization URL. With **PAR** (RFC 9126) enabled — the `usePar`
     * option, or `['use_par' => true]` here — the parameters are pushed to the IdP's
     * PAR endpoint over a back channel first, and the browser receives only
     * `client_id` + the issued one-time `request_uri`. The `state` / `nonce` / PKCE
     * code you persist are unchanged (read them via {@see getState()} /
     * {@see getNonce()} / {@see getPkceCode()}), and the push uses the same client
     * auth as the token endpoint, so PAR composes with `private_key_jwt`. Without PAR
     * this is league's standard authorization URL.
     *
     * @param array<string,mixed> $options
     */
    public function getAuthorizationUrl(array $options = []): string
    {
        $usePar = (bool) ($options['use_par'] ?? $this->usePar);
        unset($options['use_par']);
        if (!$usePar) {
            return parent::getAuthorizationUrl($options);
        }
        // Mints + stashes state, nonce and the PKCE verifier, exactly as the normal path.
        $params = $this->getAuthorizationParameters($options);
        $requestUri = $this->pushedAuthorizationRequest($params);
        $query = $this->getAuthorizationQuery([
            'client_id' => (string) $this->clientId,
            'request_uri' => $requestUri,
        ]);

        return $this->appendQuery($this->getBaseAuthorizationUrl(), $query);
    }

    /**
     * Mutate an outgoing token / PAR parameter set to carry the configured client
     * authentication. `private_key_jwt` drops any client_secret and adds the
     * client_assertion (RFC 7523); otherwise client_id / client_secret travel in the
     * POST body. Shared by the token, refresh and PAR requests so all authenticate
     * identically.
     *
     * @param array<string,mixed> $params
     * @return array<string,mixed>
     */
    private function applyClientAuth(array $params): array
    {
        if ($this->tokenEndpointAuthMethod === 'private_key_jwt') {
            unset($params['client_secret']);
            $params['client_assertion_type'] = self::CLIENT_ASSERTION_TYPE;
            $params['client_assertion'] = $this->buildClientAssertion();

            return $params;
        }
        $params['client_id'] = (string) $this->clientId;
        if ($this->clientSecret !== null && $this->clientSecret !== '') {
            $params['client_secret'] = (string) $this->clientSecret;
        }

        return $params;
    }

    /**
     * Build a signed `private_key_jwt` client-authentication assertion (RFC 7523):
     * `iss` and `sub` are the client_id, `aud` the token endpoint (the Colony accepts
     * that or the issuer), with a fresh `jti` and a short `exp` so it is single-use and
     * replay-bounded. Signed with the configured key + algorithm; the same assertion
     * authenticates the token, refresh and PAR requests.
     */
    private function buildClientAssertion(): string
    {
        $now = time();
        $claims = [
            'iss' => (string) $this->clientId,
            'sub' => (string) $this->clientId,
            'aud' => $this->endpoint('token_endpoint', '/oauth/token'),
            'jti' => bin2hex(random_bytes(32)),
            'iat' => $now,
            'exp' => $now + self::ASSERTION_LIFETIME,
        ];
        /** @var class-string $algClass */
        $algClass = 'Jose\\Component\\Signature\\Algorithm\\' . $this->signingAlg;
        $builder = new JWSBuilder(new AlgorithmManager([new $algClass()]));
        $header = ['alg' => $this->signingAlg, 'typ' => 'JWT'];
        if ($this->privateKeyId !== null && $this->privateKeyId !== '') {
            $header['kid'] = $this->privateKeyId;
        }
        $jws = $builder->create()
            ->withPayload((string) json_encode($claims))
            ->addSignature($this->signingJwk(), $header)
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /** Resolve the configured private key to a web-token JWK (a JWK, a PEM string, or a PEM file path). */
    private function signingJwk(): JWK
    {
        if ($this->privateKey instanceof JWK) {
            return $this->privateKey;
        }
        $extra = ($this->privateKeyId !== null && $this->privateKeyId !== '') ? ['kid' => $this->privateKeyId] : [];
        $key = (string) $this->privateKey;
        if (str_contains($key, '-----BEGIN')) {
            return JWKFactory::createFromKey($key, null, $extra);
        }

        return JWKFactory::createFromKeyFile($key, null, $extra);
    }

    /**
     * Push the authorization $params to the IdP's PAR endpoint (RFC 9126) and return
     * the issued one-time `request_uri`. Authenticates with the same credential as the
     * token endpoint. Throws {@see ColonyOidcException} when the IdP doesn't advertise
     * PAR, or on a transport / protocol failure.
     *
     * @param array<string,mixed> $params
     */
    private function pushedAuthorizationRequest(array $params): string
    {
        $disc = $this->discovery();
        $endpoint = $disc['pushed_authorization_request_endpoint'] ?? null;
        if (!is_string($endpoint) || $endpoint === '') {
            throw new ColonyOidcException(
                'the Colony IdP does not advertise a PAR endpoint (pushed_authorization_request_endpoint)',
            );
        }
        try {
            $response = $this->getHttpClient()->request('POST', $endpoint, [
                'form_params' => $this->applyClientAuth($params),
                'headers' => ['Accept' => 'application/json'],
            ]);
        } catch (\Throwable $e) {
            throw new ColonyOidcException('PAR request failed: ' . $endpoint, 0, $e);
        }
        $status = $response->getStatusCode();
        $data = json_decode((string) $response->getBody(), true);
        if ($status < 200 || $status >= 300 || !is_array($data)) {
            throw new ColonyOidcException('PAR endpoint returned an unexpected response (HTTP ' . $status . ')');
        }
        $requestUri = $data['request_uri'] ?? null;
        if (!is_string($requestUri) || $requestUri === '') {
            throw new ColonyOidcException('PAR response did not include a request_uri');
        }

        return $requestUri;
    }

    // -- discovery + http helpers ---------------------------------------------

    /** @return array<string,mixed> */
    private function discovery(): array
    {
        if ($this->discoveryMemo !== null) {
            return $this->discoveryMemo;
        }
        $raw = $this->cached(
            'colony_oidc_discovery_' . sha1($this->issuer),
            fn () => $this->httpGet($this->issuer . '/.well-known/openid-configuration'),
        );
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            throw new ColonyOidcException('OIDC discovery document is not valid JSON');
        }

        // Memoise first so the JWKS lookup in applySignedMetadata() doesn't re-enter
        // discovery() and recurse; then let the verified/merged doc replace it.
        $this->discoveryMemo = $data;
        if ($this->verifySignedMetadata) {
            $this->discoveryMemo = $this->applySignedMetadata($data);
        }

        return $this->discoveryMemo;
    }

    /**
     * Verify the discovery `signed_metadata` JWT (RFC 8414) against the issuer JWKS and
     * return the document with its signed claims merged in (signed values take precedence).
     * Throws {@see ColonyOidcException} when there is no `signed_metadata`, or on a bad
     * signature / issuer.
     *
     * @param array<string,mixed> $doc
     * @return array<string,mixed>
     */
    private function applySignedMetadata(array $doc): array
    {
        $raw = $doc['signed_metadata'] ?? null;
        if (!is_string($raw) || $raw === '') {
            throw new ColonyOidcException(
                'verifySignedMetadata is set but discovery has no signed_metadata (RFC 8414 §2.1)',
            );
        }
        $jwksUri = (string) ($doc['jwks_uri'] ?? $this->issuer . '/.well-known/jwks.json');
        $jwksJson = $this->cached('colony_oidc_jwks_' . sha1($jwksUri), fn () => $this->httpGet($jwksUri));
        $signed = $this->idTokenVerifier->verifySignedMetadata($raw, $jwksJson, $this->issuer);

        return array_merge($doc, $signed, ['signed_metadata' => $raw]);
    }

    private function endpoint(string $key, string $fallbackPath): string
    {
        try {
            $disc = $this->discovery();
        } catch (\Throwable) {
            return $this->issuer . $fallbackPath;
        }

        return (string) ($disc[$key] ?? $this->issuer . $fallbackPath);
    }

    private function httpGet(string $url): string
    {
        try {
            $response = $this->getHttpClient()->request('GET', $url);
        } catch (\Throwable $e) {
            throw new ColonyOidcException('OIDC fetch failed: ' . $url, 0, $e);
        }

        return (string) $response->getBody();
    }

    /** @param callable():string $producer */
    private function cached(string $key, callable $producer): string
    {
        if ($this->cache === null) {
            return $producer();
        }
        $hit = $this->cache->get($key);
        if (is_string($hit)) {
            return $hit;
        }
        $value = $producer();
        $this->cache->set($key, $value, $this->cacheTtl);

        return $value;
    }
}
