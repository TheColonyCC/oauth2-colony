<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\ColonyProvider;
use TheColony\OAuth2\ColonyResourceOwner;
use TheColony\OAuth2\Exception\ColonyOidcException;

final class ColonyProviderTest extends TestCase
{
    private const DISCOVERY = [
        'issuer' => 'https://thecolony.cc',
        'authorization_endpoint' => 'https://thecolony.cc/oauth/authorize',
        'token_endpoint' => 'https://thecolony.cc/oauth/token',
        'userinfo_endpoint' => 'https://thecolony.cc/oauth/userinfo',
        'jwks_uri' => 'https://thecolony.cc/.well-known/jwks.json',
    ];

    /** @param list<Response> $responses */
    private function provider(array $responses = [], array $options = []): ColonyProvider
    {
        $mock = new MockHandler($responses);
        $client = new Client(['handler' => HandlerStack::create($mock)]);

        return new ColonyProvider(
            array_merge([
                'clientId' => 'colony_client_abc',
                'clientSecret' => 'secret',
                'redirectUri' => 'https://app.example/auth/colony/callback',
            ], $options),
            ['httpClient' => $client],
        );
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(self::DISCOVERY));
    }

    #[Test]
    public function authorization_url_uses_discovery_and_carries_oidc_params(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getAuthorizationUrl();

        self::assertStringStartsWith('https://thecolony.cc/oauth/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('colony_client_abc', $q['client_id']);
        self::assertSame('openid profile email', $q['scope']);
        self::assertArrayHasKey('state', $q);
        self::assertArrayHasKey('nonce', $q);
        self::assertSame($q['nonce'], $provider->getNonce());
    }

    #[Test]
    public function scope_option_overrides_default(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['scope' => 'openid colony:karma']);
        $url = $provider->getAuthorizationUrl();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('openid colony:karma', $q['scope']);
    }

    #[Test]
    public function pkce_s256_is_supported(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $provider->setPkceMethod(ColonyProvider::PKCE_METHOD_S256);
        $url = $provider->getAuthorizationUrl();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('S256', $q['code_challenge_method']);
        self::assertNotEmpty($q['code_challenge']);
        self::assertNotEmpty($provider->getPkceCode());
    }

    #[Test]
    public function explicit_nonce_is_honoured(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $provider->getAuthorizationUrl(['nonce' => 'fixed-nonce']);
        self::assertSame('fixed-nonce', $provider->getNonce());
    }

    #[Test]
    public function falls_back_to_default_endpoints_when_discovery_unreachable(): void
    {
        // No queued responses → guzzle MockHandler throws on request → endpoint() swallows it.
        $provider = $this->provider([]);
        self::assertSame('https://thecolony.cc/oauth/authorize', $provider->getBaseAuthorizationUrl());
    }

    #[Test]
    public function custom_issuer_changes_endpoints_and_is_trimmed(): void
    {
        $provider = $this->provider([], ['issuer' => 'https://staging.thecolony.cc/']);
        self::assertSame('https://staging.thecolony.cc/oauth/token', $provider->getBaseAccessTokenUrl([]));
    }

    #[Test]
    public function verify_id_token_against_discovered_jwks(): void
    {
        $kit = new OidcTestKit();
        $idToken = $kit->idToken(OidcTestKit::claims());
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ]);
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $idToken]);

        $claims = $provider->verifyIdToken($token, 'nonce-xyz');
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function verify_id_token_refetches_jwks_once_after_a_key_rotation(): void
    {
        $oldKit = new OidcTestKit();   // the cached (stale) key set
        $newKit = new OidcTestKit();   // the issuer rotated to this key
        $idToken = $newKit->idToken(OidcTestKit::claims());
        $cache = new ArrayCache();
        // Pre-seed the cache with the OLD jwks so the first verify misses.
        $cache->set('colony_oidc_jwks_' . sha1('https://thecolony.cc/.well-known/jwks.json'), $oldKit->jwksJson());

        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $newKit->jwksJson()), // the fresh re-fetch
        ], ['cache' => $cache]);
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $idToken]);

        $claims = $provider->verifyIdToken($token, 'nonce-xyz');
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function verify_id_token_does_not_refetch_jwks_on_a_non_signature_failure(): void
    {
        // Cache is configured, signature is valid, but the nonce is wrong: the
        // failure must surface immediately without a (non-queued) JWKS re-fetch.
        $kit = new OidcTestKit();
        $cache = new ArrayCache();
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ], ['cache' => $cache]);
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $kit->idToken(OidcTestKit::claims())]);

        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('nonce');
        $provider->verifyIdToken($token, 'the-wrong-nonce');
    }

    #[Test]
    public function get_openid_configuration_exposes_the_discovery_document(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $conf = $provider->getOpenidConfiguration();
        self::assertSame('https://thecolony.cc/oauth/token', $conf['token_endpoint']);
    }

    #[Test]
    public function verify_id_token_requires_an_id_token(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $token = new AccessToken(['access_token' => 'at']);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('id_token');
        $provider->verifyIdToken($token, 'nonce-xyz');
    }

    #[Test]
    public function resource_owner_maps_claims(): void
    {
        $owner = new ColonyResourceOwner(OidcTestKit::claims());
        self::assertSame('colony-sub-123', $owner->getId());
        self::assertSame('colonist-one', $owner->getUsername());
        self::assertSame('agent@thecolony.cc', $owner->getEmail());
        self::assertSame('Colonist One', $owner->getDisplayName());
        self::assertArrayHasKey('iss', $owner->toArray());
    }

    #[Test]
    public function resource_owner_tolerates_missing_claims(): void
    {
        $owner = new ColonyResourceOwner([]);
        self::assertNull($owner->getId());
        self::assertNull($owner->getUsername());
        self::assertNull($owner->getEmail());
        self::assertNull($owner->getDisplayName());
    }

    #[Test]
    public function full_code_exchange_and_resource_owner_fetch(): void
    {
        $tokenBody = (string) json_encode([
            'access_token' => 'at-123',
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'id_token' => 'header.payload.sig',
        ]);
        $userinfoBody = (string) json_encode(OidcTestKit::claims());
        $provider = $this->provider([
            $this->discoveryResponse(), // resolve token_endpoint
            new Response(200, ['Content-Type' => 'application/json'], $tokenBody),
            // discovery is memoised, so the next network call is userinfo
            new Response(200, ['Content-Type' => 'application/json'], $userinfoBody),
        ]);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'auth-code']);
        self::assertSame('at-123', $token->getToken());

        $owner = $provider->getResourceOwner($token);
        self::assertInstanceOf(ColonyResourceOwner::class, $owner);
        self::assertSame('colony-sub-123', $owner->getId());
    }

    #[Test]
    public function token_endpoint_error_is_surfaced(): void
    {
        $errBody = (string) json_encode(['error' => 'invalid_grant', 'error_description' => 'bad code']);
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(400, ['Content-Type' => 'application/json'], $errBody),
        ]);

        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('bad code');
        $provider->getAccessToken('authorization_code', ['code' => 'nope']);
    }

    #[Test]
    public function token_endpoint_non_json_error_is_surfaced(): void
    {
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(503, ['Content-Type' => 'text/plain'], 'Service Unavailable'),
        ]);
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $provider->getAccessToken('authorization_code', ['code' => 'x']);
    }

    #[Test]
    public function verify_id_token_rejects_non_json_discovery(): void
    {
        $provider = $this->provider([
            new Response(200, ['Content-Type' => 'application/json'], 'not json at all'),
        ]);
        $token = new AccessToken(['access_token' => 'at', 'id_token' => 'h.p.s']);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('not valid JSON');
        $provider->verifyIdToken($token, 'nonce-xyz');
    }

    #[Test]
    public function resource_owner_details_url_comes_from_discovery(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $token = new AccessToken(['access_token' => 'at']);
        self::assertSame('https://thecolony.cc/oauth/userinfo', $provider->getResourceOwnerDetailsUrl($token));
    }

    #[Test]
    public function blank_scope_falls_back_to_openid(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['scope' => '   ']);
        $url = $provider->getAuthorizationUrl();
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('openid profile email', $q['scope']);
    }

    #[Test]
    public function discovery_is_cached_via_psr16(): void
    {
        $cache = new ArrayCache();
        // Only ONE discovery response queued; a second fetch would throw if not cached.
        $provider = $this->provider([$this->discoveryResponse()], ['cache' => $cache]);
        self::assertSame('https://thecolony.cc/oauth/token', $provider->getBaseAccessTokenUrl([]));

        // Fresh provider, same cache, no queued responses — must hit the cache.
        $provider2 = $this->provider([], ['cache' => $cache]);
        self::assertSame('https://thecolony.cc/oauth/token', $provider2->getBaseAccessTokenUrl([]));
    }

    // -- humans vs agents: ColonyResourceOwner --------------------------------

    #[Test]
    public function resource_owner_reports_a_human_subject(): void
    {
        $owner = new ColonyResourceOwner(OidcTestKit::claims(['colony_verified_human' => true]));
        self::assertTrue($owner->isHuman());
        self::assertFalse($owner->isAgent());
        self::assertTrue($owner->getVerifiedHuman());
    }

    #[Test]
    public function resource_owner_reports_an_agent_subject(): void
    {
        $owner = new ColonyResourceOwner(OidcTestKit::claims(['colony_verified_human' => false]));
        self::assertFalse($owner->isHuman());
        self::assertTrue($owner->isAgent());
        self::assertFalse($owner->getVerifiedHuman());
    }

    #[Test]
    public function resource_owner_subject_is_unknown_when_the_claim_is_absent(): void
    {
        // colony_verified_human is only emitted with the profile scope.
        $owner = new ColonyResourceOwner(OidcTestKit::claims());
        self::assertNull($owner->getVerifiedHuman());
        self::assertFalse($owner->isHuman());
        self::assertFalse($owner->isAgent());
    }

    // -- acceptSubject (RP-side audience guard) -------------------------------

    /**
     * Run a full id_token verification with the given acceptSubject restriction
     * and colony_verified_human claim override.
     *
     * @param array<string,mixed> $claimOverrides
     * @return array<string,mixed>
     */
    private function verifyWithAcceptSubject(string $acceptSubject, array $claimOverrides): array
    {
        $kit = new OidcTestKit();
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ], ['acceptSubject' => $acceptSubject]);
        $token = new AccessToken([
            'access_token' => 'at',
            'id_token' => $kit->idToken(OidcTestKit::claims($claimOverrides)),
        ]);

        return $provider->verifyIdToken($token, 'nonce-xyz');
    }

    #[Test]
    public function accept_subject_rejects_an_unknown_value_at_construction(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->provider([], ['acceptSubject' => 'robot']);
    }

    #[Test]
    public function accept_subject_human_rejects_an_agent(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('human subjects only');
        $this->verifyWithAcceptSubject('human', ['colony_verified_human' => false]);
    }

    #[Test]
    public function accept_subject_agent_rejects_a_human(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('agent subjects only');
        $this->verifyWithAcceptSubject('agent', ['colony_verified_human' => true]);
    }

    #[Test]
    public function accept_subject_human_allows_a_human(): void
    {
        $claims = $this->verifyWithAcceptSubject('human', ['colony_verified_human' => true]);
        self::assertTrue($claims['colony_verified_human']);
    }

    #[Test]
    public function accept_subject_agent_allows_an_agent(): void
    {
        $claims = $this->verifyWithAcceptSubject('agent', ['colony_verified_human' => false]);
        self::assertFalse($claims['colony_verified_human']);
    }

    #[Test]
    public function accept_subject_restrictive_without_the_claim_raises(): void
    {
        // profile scope not requested -> no colony_verified_human -> never silently allow
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('profile');
        $this->verifyWithAcceptSubject('human', []);
    }

    #[Test]
    public function accept_subject_any_never_raises_on_subject_type(): void
    {
        $claims = $this->verifyWithAcceptSubject('any', ['colony_verified_human' => false]);
        self::assertSame('colony-sub-123', $claims['sub']);
        // and with the claim absent entirely
        $claims2 = $this->verifyWithAcceptSubject('any', []);
        self::assertArrayNotHasKey('colony_verified_human', $claims2);
    }

    // -- RP-initiated logout: getEndSessionUrl --------------------------------

    #[Test]
    public function end_session_url_reads_discovery_and_carries_supplied_params(): void
    {
        $disc = array_merge(self::DISCOVERY, ['end_session_endpoint' => 'https://thecolony.cc/oauth/end-session']);
        $provider = $this->provider([
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($disc)),
        ]);
        $url = $provider->getEndSessionUrl(
            idTokenHint: 'idt.123',
            postLogoutRedirectUri: 'https://app.example/bye?a=b',
            state: 'xyz',
        );
        self::assertStringStartsWith('https://thecolony.cc/oauth/end-session?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('colony_client_abc', $q['client_id']);
        self::assertSame('idt.123', $q['id_token_hint']);
        self::assertSame('https://app.example/bye?a=b', $q['post_logout_redirect_uri']);
        self::assertSame('xyz', $q['state']);
    }

    #[Test]
    public function end_session_url_omits_unset_params_and_falls_back_without_http(): void
    {
        // No queued responses: discovery is unreachable, endpoint() falls back —
        // and getEndSessionUrl must still produce a usable URL with only client_id.
        $provider = $this->provider([]);
        $url = $provider->getEndSessionUrl();
        self::assertStringStartsWith('https://thecolony.cc/oauth/end-session?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame(['client_id' => 'colony_client_abc'], $q);
    }
}
