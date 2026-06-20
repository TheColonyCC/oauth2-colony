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
}
