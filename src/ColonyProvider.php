<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use Psr\SimpleCache\CacheInterface;
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

        return $params;
    }

    /** The nonce minted for the last authorization URL — persist it to verify the id_token. */
    public function getNonce(): ?string
    {
        return $this->nonce;
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
     * Verify the id_token's signature against the issuer JWKS and its core
     * claims, returning the claim set.
     *
     * When a cache is configured, the JWKS is re-fetched once if verification
     * fails against the cached set — this transparently rides out a signing-key
     * rotation at the issuer without waiting for the cache TTL to lapse.
     *
     * @return array<string,mixed>
     */
    public function verifyIdToken(AccessToken $token, string $expectedNonce, ?int $now = null): array
    {
        $idToken = $this->getIdToken($token);
        if ($idToken === null) {
            throw new ColonyOidcException('token response did not include an id_token');
        }
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

        return $claims;
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

        return $this->discoveryMemo = $data;
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
