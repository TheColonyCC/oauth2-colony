<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\ColonyProvider;
use TheColony\OAuth2\ColonyResourceOwner;
use TheColony\OAuth2\IdTokenVerifier;
use TheColony\OAuth2\Exception\ColonyConsentRequiredException;
use TheColony\OAuth2\Exception\ColonyLoginRequiredException;
use TheColony\OAuth2\Exception\ColonyOidcException;

final class ColonyProviderTest extends TestCase
{
    private const DISCOVERY = [
        'issuer' => 'https://thecolony.ai',
        'authorization_endpoint' => 'https://thecolony.ai/oauth/authorize',
        'token_endpoint' => 'https://thecolony.ai/oauth/token',
        'userinfo_endpoint' => 'https://thecolony.ai/oauth/userinfo',
        'jwks_uri' => 'https://thecolony.ai/.well-known/jwks.json',
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

    /**
     * Like {@see provider()} but records every outgoing request into $history so a test
     * can inspect the body the provider actually sent. Omits the default clientSecret so
     * private_key_jwt configs don't carry one.
     *
     * @param list<Response> $responses
     * @param array<int,mixed> $history
     * @param array<string,mixed> $options
     */
    private function providerWithHistory(array $responses, array &$history, array $options = []): ColonyProvider
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($history));
        $client = new Client(['handler' => $stack]);

        return new ColonyProvider(array_merge([
            'clientId' => 'colony_client_abc',
            'redirectUri' => 'https://app.example/auth/colony/callback',
        ], $options), ['httpClient' => $client]);
    }

    #[Test]
    public function authorization_url_uses_discovery_and_carries_oidc_params(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getAuthorizationUrl();

        self::assertStringStartsWith('https://thecolony.ai/oauth/authorize?', $url);
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
        self::assertSame('https://thecolony.ai/oauth/authorize', $provider->getBaseAuthorizationUrl());
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
        $cache->set('colony_oidc_jwks_' . sha1('https://thecolony.ai/.well-known/jwks.json'), $oldKit->jwksJson());

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
        self::assertSame('https://thecolony.ai/oauth/token', $conf['token_endpoint']);
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

    // ---- RFC 8693 token exchange (the agent-native path) --------------------

    #[Test]
    public function token_exchange_returns_an_audience_scoped_id_token(): void
    {
        $kit = new OidcTestKit();
        $idToken = $kit->idToken(OidcTestKit::claims(['aud' => 'colony_client_abc']));
        $tokenBody = (string) json_encode([
            'access_token' => 'exch-at',
            'issued_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'token_type' => 'Bearer',
            'expires_in' => 900,
            'id_token' => $idToken,
        ]);
        $history = [];
        $provider = $this->providerWithHistory([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], $tokenBody),
        ], $history, ['clientSecret' => 'secret']);

        $token = $provider->exchangeToken('the-agent-jwt', 'colony_client_abc');
        self::assertSame('exch-at', $token->getToken());
        self::assertSame($idToken, $token->getValues()['id_token']);

        parse_str((string) $history[1]['request']->getBody(), $sent);
        self::assertSame('urn:ietf:params:oauth:grant-type:token-exchange', $sent['grant_type']);
        self::assertSame('the-agent-jwt', $sent['subject_token']);
        self::assertSame('urn:ietf:params:oauth:token-type:access_token', $sent['subject_token_type']);
        self::assertSame('colony_client_abc', $sent['audience']);
        self::assertSame('openid profile', $sent['scope']);
    }

    #[Test]
    public function token_exchange_defaults_audience_to_the_client_id(): void
    {
        $kit = new OidcTestKit();
        $tokenBody = (string) json_encode(['access_token' => 'x', 'id_token' => $kit->idToken(OidcTestKit::claims())]);
        $history = [];
        $provider = $this->providerWithHistory([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], $tokenBody),
        ], $history);

        $provider->exchangeToken('jwt-only');
        parse_str((string) $history[1]['request']->getBody(), $sent);
        self::assertSame('colony_client_abc', $sent['audience']);
    }

    #[Test]
    public function token_exchange_surfaces_oauth_errors(): void
    {
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(400, ['Content-Type' => 'application/json'], (string) json_encode([
                'error' => 'invalid_target', 'error_description' => 'audience not allowed',
            ])),
        ]);
        $this->expectException(\League\OAuth2\Client\Provider\Exception\IdentityProviderException::class);
        $this->expectExceptionMessage('audience not allowed');
        $provider->exchangeToken('jwt', 'bad-aud');
    }

    #[Test]
    public function exchanged_id_token_verifies_with_a_null_nonce(): void
    {
        $kit = new OidcTestKit();
        $claims = OidcTestKit::claims();
        unset($claims['nonce']); // exchanged id_tokens carry no nonce
        $idToken = $kit->idToken($claims);
        $tokenBody = (string) json_encode(['access_token' => 'x', 'id_token' => $idToken]);
        $provider = $this->provider([
            $this->discoveryResponse(),                  // resolve token_endpoint (memoised after)
            new Response(200, ['Content-Type' => 'application/json'], $tokenBody),
            new Response(200, [], $kit->jwksJson()),     // verifyIdToken's JWKS fetch
        ]);

        $token = $provider->exchangeToken('agent-jwt');
        $verified = $provider->verifyIdToken($token, null);
        self::assertSame('colonist-one', $verified['preferred_username']);
    }

    #[Test]
    public function verify_presented_id_token_verifies_a_raw_string(): void
    {
        // The headless-agent RP path: the agent exchanged + presents a raw id_token,
        // the relying party only verifies it — no AccessToken wrapper to build.
        $kit = new OidcTestKit();
        $claims = OidcTestKit::claims();
        unset($claims['nonce']); // a presented/exchanged token carries no nonce
        $idToken = $kit->idToken($claims);
        $provider = $this->provider([
            $this->discoveryResponse(),               // resolve issuer + jwks_uri
            new Response(200, [], $kit->jwksJson()),  // JWKS fetch
        ]);

        $verified = $provider->verifyPresentedIdToken($idToken, null);
        self::assertSame('colonist-one', $verified['preferred_username']);
    }

    #[Test]
    public function verify_presented_id_token_rejects_a_token_for_another_audience(): void
    {
        $kit = new OidcTestKit();
        $idToken = $kit->idToken(OidcTestKit::claims(['aud' => 'another_client']));
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('audience');
        $provider->verifyPresentedIdToken($idToken, null);
    }

    #[Test]
    public function verify_presented_id_token_rejects_a_token_from_another_signer(): void
    {
        // The RP-model boundary (Reticuli, 2026-07): a *raw Colony token* — or
        // anything not minted for this RP by the Colony's OIDC signer — must NOT
        // authenticate. Correct-looking claims, wrong signing key → the signature
        // check fails. This is the negative test the README prescribes: don't
        // accept-and-exchange a presented token; verify it, and prove a foreign
        // token is turned away.
        $foreignKit = new OidcTestKit();          // a DIFFERENT signing key
        $realKit = new OidcTestKit();
        $claims = OidcTestKit::claims();
        unset($claims['nonce']);
        $idToken = $foreignKit->idToken($claims);
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $realKit->jwksJson()),   // the genuine issuer JWKS
        ]);
        $this->expectException(ColonyOidcException::class);
        $provider->verifyPresentedIdToken($idToken, null);
    }

    #[Test]
    public function verify_presented_id_token_rejects_an_opaque_non_jwt(): void
    {
        // An opaque bearer (e.g. a raw Colony API key) is not an id_token at all.
        $kit = new OidcTestKit();
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ]);
        $this->expectException(ColonyOidcException::class);
        $provider->verifyPresentedIdToken('opaque-not-a-jwt', null);
    }

    #[Test]
    public function verify_id_token_and_verify_presented_id_token_agree(): void
    {
        // Delegation equivalence: the wrapper path and the raw-string path return
        // the identical claim set for the same token.
        $kit = new OidcTestKit();
        $claims = OidcTestKit::claims();
        unset($claims['nonce']);
        $idToken = $kit->idToken($claims);
        $tokenBody = (string) json_encode(['access_token' => 'x', 'id_token' => $idToken]);
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], $tokenBody),
            new Response(200, [], $kit->jwksJson()),  // wrapper path JWKS fetch
            new Response(200, [], $kit->jwksJson()),  // raw path JWKS fetch
        ]);

        $token = $provider->exchangeToken('agent-jwt');
        self::assertSame(
            $provider->verifyIdToken($token, null),
            $provider->verifyPresentedIdToken($kit->idToken($claims), null),
        );
    }

    #[Test]
    public function colony_operator_id_reads_the_claim(): void
    {
        $provider = $this->provider();
        self::assertSame(
            'op_ABC123',
            $provider->colonyOperatorId(['colony_operator_id' => 'op_ABC123']),
        );
    }

    #[Test]
    public function colony_operator_id_is_null_when_absent(): void
    {
        // The opt-in / withheld case — RPs MUST degrade gracefully, so the
        // accessor returns null rather than raising.
        $provider = $this->provider();
        self::assertNull($provider->colonyOperatorId(OidcTestKit::claims()));
        self::assertNull($provider->colonyOperatorId([]));
    }

    #[Test]
    public function colony_operator_id_rejects_non_string_or_empty(): void
    {
        $provider = $this->provider();
        self::assertNull($provider->colonyOperatorId(['colony_operator_id' => '']));
        self::assertNull($provider->colonyOperatorId(['colony_operator_id' => 123]));
        self::assertNull($provider->colonyOperatorId(['colony_operator_id' => null]));
    }

    #[Test]
    public function colony_action_binding_reads_the_claim(): void
    {
        $provider = $this->provider();
        self::assertSame(
            'sha256:deadbeef',
            $provider->colonyActionBinding(['colony_action_binding' => 'sha256:deadbeef']),
        );
    }

    #[Test]
    public function colony_action_binding_is_null_when_absent(): void
    {
        // No action bound (a plain login-consent) — an RP MUST treat null as
        // "the human authenticated but did not approve a specific action".
        $provider = $this->provider();
        self::assertNull($provider->colonyActionBinding(OidcTestKit::claims()));
        self::assertNull($provider->colonyActionBinding([]));
    }

    #[Test]
    public function colony_action_binding_rejects_non_string_or_empty(): void
    {
        $provider = $this->provider();
        self::assertNull($provider->colonyActionBinding(['colony_action_binding' => '']));
        self::assertNull($provider->colonyActionBinding(['colony_action_binding' => 123]));
        self::assertNull($provider->colonyActionBinding(['colony_action_binding' => null]));
    }

    // --- Organisation-scoped delegation (F2) ----------------------------------
    // "Agent may act AS the org." A member-delegated access token carries an
    // RFC 8693 `act` naming the org + an RFC 9396 authorization_details hint.

    /** A verified public-org delegated token, as the Colony mints it. */
    private const ORG_DELEGATED_CLAIMS = [
        'sub' => 'agent-pairwise-xyz',
        'aud' => 'https://vendor.example',
        'scope' => 'orders:write',
        'act' => ['sub' => 'colony_org:acme', 'org_verified_domain' => 'acme.com'],
        'authorization_details' => [
            ['type' => 'colony_org_delegation', 'org' => 'colony_org:acme',
             'granted_by' => 'org_policy', 'max_amount' => 500],
        ],
    ];

    #[Test]
    public function acting_as_org_reads_the_act_subject(): void
    {
        $provider = $this->provider();
        self::assertSame(
            'colony_org:acme',
            $provider->colonyActingAsOrg(self::ORG_DELEGATED_CLAIMS),
        );
        self::assertSame(
            'acme.com',
            $provider->colonyActingAsOrgVerifiedDomain(self::ORG_DELEGATED_CLAIMS),
        );
    }

    #[Test]
    public function acting_as_org_reads_the_delegation_constraints(): void
    {
        $provider = $this->provider();
        $rar = $provider->colonyOrgDelegation(self::ORG_DELEGATED_CLAIMS);
        self::assertIsArray($rar);
        self::assertSame('colony_org:acme', $rar['org']);
        self::assertSame(500, $rar['max_amount']);
    }

    #[Test]
    public function opaque_org_delegation_has_no_verified_domain(): void
    {
        // An opaque org's act.sub is a per-client pairwise code, and it never
        // discloses a real slug or domain.
        $provider = $this->provider();
        $claims = ['act' => ['sub' => 'colony_org:pairwise-abc123']];
        self::assertSame('colony_org:pairwise-abc123', $provider->colonyActingAsOrg($claims));
        self::assertNull($provider->colonyActingAsOrgVerifiedDomain($claims));
    }

    #[Test]
    public function acting_as_org_is_null_for_non_org_tokens(): void
    {
        $provider = $this->provider();
        // A plain login token — no act at all.
        self::assertNull($provider->colonyActingAsOrg(OidcTestKit::claims()));
        self::assertNull($provider->colonyActingAsOrgVerifiedDomain(OidcTestKit::claims()));
        self::assertNull($provider->colonyOrgDelegation(OidcTestKit::claims()));
        // A user-delegation act (names a user, not an org) is NOT org-delegation.
        $userAct = ['act' => ['sub' => 'user-123']];
        self::assertNull($provider->colonyActingAsOrg($userAct));
        // Malformed shapes degrade to null, never raise.
        self::assertNull($provider->colonyActingAsOrg(['act' => 'not-an-array']));
        self::assertNull($provider->colonyOrgDelegation(['authorization_details' => 'nope']));
        self::assertNull($provider->colonyOrgDelegation(
            ['authorization_details' => [['type' => 'openid_credential']]],
        ));
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
    public function resource_owner_exposes_acr_amr_sid_and_auth_time(): void
    {
        $owner = new ColonyResourceOwner(OidcTestKit::claims([
            'acr' => 'mfa',
            'amr' => ['pwd', 'otp', 'mfa'],
            'sid' => 'sess_42',
            'auth_time' => 1700000000,
        ]));
        self::assertSame('mfa', $owner->getAcr());
        self::assertSame(['pwd', 'otp', 'mfa'], $owner->getAmr());
        self::assertTrue($owner->isMfa());
        self::assertSame('sess_42', $owner->getSid());
        self::assertSame(1700000000, $owner->getAuthTime());
    }

    #[Test]
    public function resource_owner_acr_fields_absent_are_null(): void
    {
        $owner = new ColonyResourceOwner(OidcTestKit::claims());
        self::assertNull($owner->getAcr());
        self::assertSame([], $owner->getAmr());
        self::assertFalse($owner->isMfa());
        self::assertNull($owner->getSid());
        self::assertNull($owner->getAuthTime());
    }

    #[Test]
    public function require_acr_sends_acr_values_on_the_authorization_url(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['requireAcr' => 'mfa']);
        parse_str((string) parse_url($provider->getAuthorizationUrl(), PHP_URL_QUERY), $q);
        self::assertSame('mfa', $q['acr_values']);
    }

    #[Test]
    public function explicit_acr_values_option_overrides_require_acr(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['requireAcr' => 'mfa']);
        parse_str((string) parse_url($provider->getAuthorizationUrl(['acr_values' => 'single']), PHP_URL_QUERY), $q);
        self::assertSame('single', $q['acr_values']);
    }

    #[Test]
    public function no_acr_values_when_require_acr_unset(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        parse_str((string) parse_url($provider->getAuthorizationUrl(), PHP_URL_QUERY), $q);
        self::assertArrayNotHasKey('acr_values', $q);
    }

    #[Test]
    public function max_age_and_login_hint_pass_through_to_the_authorization_url(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getAuthorizationUrl(['max_age' => 3600, 'login_hint' => 'colonist-one']);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('3600', $q['max_age']);
        self::assertSame('colonist-one', $q['login_hint']);
    }

    #[Test]
    public function verify_id_token_enforces_require_acr(): void
    {
        $kit = new OidcTestKit();
        $idToken = $kit->idToken(OidcTestKit::claims(['acr' => 'single', 'amr' => ['pwd']]));
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $idToken]);
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ], ['requireAcr' => 'mfa']);

        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage("requires acr='mfa'");
        $provider->verifyIdToken($token, 'nonce-xyz');
    }

    #[Test]
    public function verify_id_token_accepts_satisfied_require_acr(): void
    {
        $kit = new OidcTestKit();
        $idToken = $kit->idToken(OidcTestKit::claims(['acr' => 'mfa', 'amr' => ['pwd', 'otp', 'mfa']]));
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $idToken]);
        $provider = $this->provider([
            $this->discoveryResponse(),
            new Response(200, [], $kit->jwksJson()),
        ], ['requireAcr' => 'mfa']);

        $claims = $provider->verifyIdToken($token, 'nonce-xyz');
        self::assertSame('mfa', $claims['acr']);
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
        self::assertSame('https://thecolony.ai/oauth/userinfo', $provider->getResourceOwnerDetailsUrl($token));
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
        self::assertSame('https://thecolony.ai/oauth/token', $provider->getBaseAccessTokenUrl([]));

        // Fresh provider, same cache, no queued responses — must hit the cache.
        $provider2 = $this->provider([], ['cache' => $cache]);
        self::assertSame('https://thecolony.ai/oauth/token', $provider2->getBaseAccessTokenUrl([]));
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
        $disc = array_merge(self::DISCOVERY, ['end_session_endpoint' => 'https://thecolony.ai/oauth/end-session']);
        $provider = $this->provider([
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($disc)),
        ]);
        $url = $provider->getEndSessionUrl(
            idTokenHint: 'idt.123',
            postLogoutRedirectUri: 'https://app.example/bye?a=b',
            state: 'xyz',
        );
        self::assertStringStartsWith('https://thecolony.ai/oauth/end-session?', $url);
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
        self::assertStringStartsWith('https://thecolony.ai/oauth/end-session?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame(['client_id' => 'colony_client_abc'], $q);
    }

    // -- back-channel logout: validateLogoutToken ----------------------------

    private const BCL = IdTokenVerifier::BACKCHANNEL_LOGOUT_EVENT;

    /** @param array<string,mixed> $over @return array<string,mixed> */
    private function logoutClaims(array $over = []): array
    {
        return array_merge([
            'iss' => 'https://thecolony.ai', 'aud' => 'colony_client_abc',
            'iat' => time(), 'exp' => time() + 120, 'jti' => 'logout-jti-1',
            'sub' => 'agent_123', 'sid' => 'sess_42',
            'events' => [self::BCL => []],
        ], $over);
    }

    #[Test]
    public function validate_logout_token_valid_returns_sub_and_sid(): void
    {
        $kit = new OidcTestKit();
        $provider = $this->provider([$this->discoveryResponse(), new Response(200, [], $kit->jwksJson())]);
        $claims = $provider->validateLogoutToken($kit->idToken($this->logoutClaims()));
        self::assertSame('agent_123', $claims['sub']);
        self::assertSame('sess_42', $claims['sid']);
        self::assertArrayHasKey(self::BCL, $claims['events']);
    }

    #[Test]
    public function validate_logout_token_sub_only_and_sid_only(): void
    {
        $kit = new OidcTestKit();
        $p = $this->provider([$this->discoveryResponse(), new Response(200, [], $kit->jwksJson())]);
        $c = $this->logoutClaims(); unset($c['sid']);
        self::assertSame('agent_123', $p->validateLogoutToken($kit->idToken($c))['sub']);
        $p2 = $this->provider([$this->discoveryResponse(), new Response(200, [], $kit->jwksJson())]);
        $c2 = $this->logoutClaims(); unset($c2['sub']);
        self::assertSame('sess_42', $p2->validateLogoutToken($kit->idToken($c2))['sid']);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidLogoutTokens')]
    #[Test]
    public function validate_logout_token_rejects(callable $mutate): void
    {
        $kit = new OidcTestKit();
        $provider = $this->provider([$this->discoveryResponse(), new Response(200, [], $kit->jwksJson())]);
        $claims = $this->logoutClaims();
        $token = $mutate($kit, $claims);
        $this->expectException(ColonyOidcException::class);
        $provider->validateLogoutToken($token);
    }

    /** @return array<string,array{0:callable}> */
    public static function invalidLogoutTokens(): array
    {
        return [
            'wrong issuer' => [fn ($k, $c) => $k->idToken(['iss' => 'https://evil.example'] + $c)],
            'wrong audience' => [fn ($k, $c) => $k->idToken(['aud' => 'someone_else'] + $c)],
            'missing iat' => [function ($k, $c) { unset($c['iat']); return $k->idToken($c); }],
            'expired' => [fn ($k, $c) => $k->idToken(['exp' => time() - 3600] + $c)],
            'nonce present' => [fn ($k, $c) => $k->idToken(['nonce' => 'N'] + $c)],
            'neither sub nor sid' => [function ($k, $c) { unset($c['sub'], $c['sid']); return $k->idToken($c); }],
            'missing events' => [function ($k, $c) { unset($c['events']); return $k->idToken($c); }],
            'events not object' => [fn ($k, $c) => $k->idToken(['events' => 'nope'] + $c)],
            'wrong event member' => [fn ($k, $c) => $k->idToken(['events' => ['http://x/other' => []]] + $c)],
            'bad signature' => [fn ($k, $c) => (new OidcTestKit())->idToken($c)],
        ];
    }

    #[Test]
    public function validate_logout_token_verifies_against_multikey_jwks(): void
    {
        $k1 = new OidcTestKit();
        $k2 = new OidcTestKit();   // the token will be signed by k2
        $jwks = (string) json_encode(['keys' => [
            json_decode($k1->jwksJson(), true)['keys'][0],
            json_decode($k2->jwksJson(), true)['keys'][0],
        ]]);
        $provider = $this->provider([$this->discoveryResponse(), new Response(200, [], $jwks)]);
        $claims = $provider->validateLogoutToken($k2->idToken($this->logoutClaims()));
        self::assertSame('agent_123', $claims['sub']);
    }

    #[Test]
    public function verify_id_token_verifies_against_multikey_jwks(): void
    {
        $k1 = new OidcTestKit();
        $k2 = new OidcTestKit();
        $jwks = (string) json_encode(['keys' => [
            json_decode($k1->jwksJson(), true)['keys'][0],
            json_decode($k2->jwksJson(), true)['keys'][0],
        ]]);
        $provider = $this->provider([$this->discoveryResponse(), new Response(200, [], $jwks)]);
        $token = new AccessToken(['access_token' => 'at', 'id_token' => $k2->idToken(OidcTestKit::claims())]);
        self::assertSame('colony-sub-123', $provider->verifyIdToken($token, 'nonce-xyz')['sub']);
    }

    // -- RFC 9207 authorization-response iss validation -----------------------

    #[Test]
    public function validate_authorization_response_issuer_accepts_a_matching_iss(): void
    {
        $provider = $this->provider([]);
        $provider->validateAuthorizationResponseIssuer(['code' => 'abc', 'iss' => 'https://thecolony.ai']);
        self::assertTrue(true);   // no exception thrown
    }

    #[Test]
    public function validate_authorization_response_issuer_rejects_a_missing_iss(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('missing iss');
        $provider->validateAuthorizationResponseIssuer(['code' => 'abc']);
    }

    #[Test]
    public function validate_authorization_response_issuer_rejects_an_empty_iss(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('missing iss');
        $provider->validateAuthorizationResponseIssuer(['code' => 'abc', 'iss' => '']);
    }

    #[Test]
    public function validate_authorization_response_issuer_rejects_a_mismatched_iss(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('issuer mismatch');
        $provider->validateAuthorizationResponseIssuer(['code' => 'abc', 'iss' => 'https://evil.example']);
    }

    #[Test]
    public function validate_authorization_response_issuer_honours_a_custom_issuer(): void
    {
        $provider = $this->provider([], ['issuer' => 'https://staging.thecolony.cc/']);
        // The configured issuer is rtrim('/')-normalised, so the unslashed form must match.
        $provider->validateAuthorizationResponseIssuer(['iss' => 'https://staging.thecolony.cc']);
        self::assertTrue(true);
    }

    // -- front-channel logout: validateFrontChannelLogout ---------------------

    #[Test]
    public function validate_front_channel_logout_accepts_a_valid_iss_and_sid(): void
    {
        $provider = $this->provider([]);
        $provider->validateFrontChannelLogout(['iss' => 'https://thecolony.ai', 'sid' => 'sess_42']);
        self::assertTrue(true);   // no exception thrown
    }

    #[Test]
    public function validate_front_channel_logout_rejects_a_missing_iss(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('missing iss');
        $provider->validateFrontChannelLogout(['sid' => 'sess_42']);
    }

    #[Test]
    public function validate_front_channel_logout_rejects_a_mismatched_iss(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('issuer mismatch');
        $provider->validateFrontChannelLogout(['iss' => 'https://evil.example', 'sid' => 'sess_42']);
    }

    #[Test]
    public function validate_front_channel_logout_rejects_a_missing_sid(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('missing sid');
        $provider->validateFrontChannelLogout(['iss' => 'https://thecolony.ai']);
    }

    #[Test]
    public function validate_front_channel_logout_rejects_an_empty_sid(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('missing sid');
        $provider->validateFrontChannelLogout(['iss' => 'https://thecolony.ai', 'sid' => '']);
    }

    // -- silent SSO ----------------------------------------------------------

    #[Test]
    public function silent_authorization_url_sets_prompt_none(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getSilentAuthorizationUrl(['scope' => 'openid profile']);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('none', $q['prompt']);
        self::assertSame('openid profile', $q['scope']);
    }

    #[Test]
    public function silent_authorization_url_overrides_passed_prompt(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getSilentAuthorizationUrl(['prompt' => 'login']);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('none', $q['prompt']);
    }

    #[Test]
    public function raise_for_callback_error_login_required(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyLoginRequiredException::class);
        $provider->raiseForCallbackError(['error' => 'login_required']);
    }

    #[Test]
    public function raise_for_callback_error_consent_required(): void
    {
        $provider = $this->provider([]);
        $this->expectException(ColonyConsentRequiredException::class);
        $provider->raiseForCallbackError(['error' => 'consent_required', 'error_description' => 'needs consent']);
    }

    #[Test]
    public function raise_for_callback_error_generic_is_base_exception(): void
    {
        $provider = $this->provider([]);
        try {
            $provider->raiseForCallbackError(['error' => 'interaction_required']);
            self::fail('expected an exception');
        } catch (ColonyOidcException $e) {
            self::assertNotInstanceOf(ColonyLoginRequiredException::class, $e);
            self::assertNotInstanceOf(ColonyConsentRequiredException::class, $e);
        }
    }

    #[Test]
    public function raise_for_callback_error_noop_on_clean_code(): void
    {
        $provider = $this->provider([]);
        $provider->raiseForCallbackError(['code' => 'abc', 'state' => 'xyz']);
        self::assertTrue(true);   // no exception thrown
    }

    // -- granular consent: grantedScopes -------------------------------------

    #[Test]
    public function granted_scopes_parsed_from_token_response(): void
    {
        $provider = $this->provider([]);
        $token = new AccessToken(['access_token' => 'at', 'scope' => 'openid profile']);
        self::assertSame(['openid', 'profile'], $provider->grantedScopes($token));
    }

    #[Test]
    public function granted_scopes_falls_back_to_requested_when_omitted(): void
    {
        // RFC 6749 §5.1: server MAY omit scope when it equals the request.
        $provider = $this->provider([]);
        $token = new AccessToken(['access_token' => 'at']);   // no scope key
        self::assertSame(['openid', 'profile', 'email'],
            $provider->grantedScopes($token, 'openid profile email'));
        self::assertSame([], $provider->grantedScopes($token));   // no fallback -> empty
    }

    // -- client auth: private_key_jwt (RFC 7523) ------------------------------

    #[Test]
    public function token_auth_method_rejects_an_unknown_value(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('tokenEndpointAuthMethod');
        $this->provider([], ['tokenEndpointAuthMethod' => 'client_secret_jwt']);
    }

    #[Test]
    public function private_key_jwt_requires_a_private_key(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('privateKey is required');
        $this->provider([], ['tokenEndpointAuthMethod' => 'private_key_jwt']);
    }

    #[Test]
    public function private_key_jwt_rejects_a_non_asymmetric_signing_alg(): void
    {
        $kit = new OidcTestKit();
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('signingAlg');
        $this->provider([], [
            'tokenEndpointAuthMethod' => 'private_key_jwt',
            'privateKey' => $kit->key,
            'signingAlg' => 'HS256',
        ]);
    }

    #[Test]
    public function client_secret_post_constructs_without_a_secret_for_dormant_use(): void
    {
        // A dormant/unconfigured client_secret_post provider (empty secret) must construct
        // fine — league's default, and what the colony-login-bundle lazy service + dormant
        // "button hidden / routes 404 until env set" pattern relies on. It only fails if an
        // actual token request is attempted without a secret.
        $h = [];   // providerWithHistory omits the default secret
        $provider = $this->providerWithHistory([$this->discoveryResponse()], $h);
        self::assertSame('https://thecolony.ai/oauth/authorize', $provider->getBaseAuthorizationUrl());
    }

    #[Test]
    public function private_key_jwt_authenticates_the_token_request_with_a_signed_assertion(): void
    {
        $kit = new OidcTestKit();
        $history = [];
        $provider = $this->providerWithHistory([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'],
                (string) json_encode(['access_token' => 'at-1', 'token_type' => 'Bearer'])),
        ], $history, [
            'tokenEndpointAuthMethod' => 'private_key_jwt',
            'privateKey' => $kit->key,
            'privateKeyId' => 'test-1',
        ]);

        $token = $provider->getAccessToken('authorization_code', ['code' => 'auth-code']);
        self::assertSame('at-1', $token->getToken());

        // Inspect the body the provider actually POSTed to the token endpoint.
        $sentBody = (string) end($history)['request']->getBody();
        parse_str($sentBody, $body);
        self::assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $body['client_assertion_type']);
        self::assertArrayHasKey('client_assertion', $body);
        self::assertArrayNotHasKey('client_secret', $body);

        // The assertion must verify against the public key and carry the right claims.
        $jws = (new CompactSerializer())->unserialize($body['client_assertion']);
        $verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
        self::assertTrue($verifier->verifyWithKey($jws, $kit->key->toPublic(), 0));
        self::assertSame('test-1', $jws->getSignature(0)->getProtectedHeader()['kid']);
        $claims = json_decode((string) $jws->getPayload(), true);
        self::assertSame('colony_client_abc', $claims['iss']);
        self::assertSame('colony_client_abc', $claims['sub']);
        self::assertSame('https://thecolony.ai/oauth/token', $claims['aud']);
        self::assertNotEmpty($claims['jti']);
        self::assertGreaterThan(time(), $claims['exp']);
    }

    #[Test]
    public function private_key_jwt_also_authenticates_the_refresh_request(): void
    {
        $kit = new OidcTestKit();
        $history = [];
        $provider = $this->providerWithHistory([
            $this->discoveryResponse(),
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(['access_token' => 'at-2'])),
        ], $history, ['tokenEndpointAuthMethod' => 'private_key_jwt', 'privateKey' => $kit->key]);

        $provider->getAccessToken('refresh_token', ['refresh_token' => 'rt-1']);
        parse_str((string) end($history)['request']->getBody(), $body);
        self::assertArrayHasKey('client_assertion', $body);
        self::assertSame('rt-1', $body['refresh_token']);
        self::assertArrayNotHasKey('client_secret', $body);
    }

    // -- PAR (RFC 9126) -------------------------------------------------------

    #[Test]
    public function par_pushes_parameters_and_returns_a_request_uri_url(): void
    {
        $history = [];
        $disc = array_merge(self::DISCOVERY, ['pushed_authorization_request_endpoint' => 'https://thecolony.ai/oauth/par']);
        $provider = $this->providerWithHistory([
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($disc)),
            new Response(201, ['Content-Type' => 'application/json'],
                (string) json_encode(['request_uri' => 'urn:colony:par:abc123', 'expires_in' => 60])),
        ], $history, ['clientSecret' => 'secret', 'usePar' => true]);

        $url = $provider->getAuthorizationUrl(['scope' => 'openid profile']);

        // The browser URL carries ONLY client_id + request_uri.
        self::assertStringStartsWith('https://thecolony.ai/oauth/authorize?', $url);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertEqualsCanonicalizing(['client_id', 'request_uri'], array_keys($q));
        self::assertSame('urn:colony:par:abc123', $q['request_uri']);
        self::assertSame('colony_client_abc', $q['client_id']);

        // The push (2nd HTTP call) carried the real authorization params + client auth.
        $par = end($history)['request'];
        self::assertSame('https://thecolony.ai/oauth/par', (string) $par->getUri());
        self::assertSame('POST', $par->getMethod());
        parse_str((string) $par->getBody(), $pushed);
        self::assertSame('code', $pushed['response_type']);
        self::assertSame('openid profile', $pushed['scope']);
        self::assertArrayHasKey('state', $pushed);
        self::assertArrayHasKey('nonce', $pushed);
        self::assertSame('secret', $pushed['client_secret']);   // client_secret_post auth on the push

        // state / nonce are retrievable as on the normal path.
        self::assertSame($pushed['state'], $provider->getState());
        self::assertSame($pushed['nonce'], $provider->getNonce());
    }

    #[Test]
    public function par_composes_with_private_key_jwt(): void
    {
        $kit = new OidcTestKit();
        $history = [];
        $disc = array_merge(self::DISCOVERY, ['pushed_authorization_request_endpoint' => 'https://thecolony.ai/oauth/par']);
        $provider = $this->providerWithHistory([
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($disc)),
            new Response(201, ['Content-Type' => 'application/json'], (string) json_encode(['request_uri' => 'urn:colony:par:xyz'])),
        ], $history, ['tokenEndpointAuthMethod' => 'private_key_jwt', 'privateKey' => $kit->key, 'usePar' => true]);

        $provider->getAuthorizationUrl();
        parse_str((string) end($history)['request']->getBody(), $pushed);
        self::assertArrayNotHasKey('client_secret', $pushed);
        self::assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $pushed['client_assertion_type']);
        self::assertArrayHasKey('client_assertion', $pushed);
    }

    #[Test]
    public function par_can_be_enabled_per_call(): void
    {
        $history = [];
        $disc = array_merge(self::DISCOVERY, ['pushed_authorization_request_endpoint' => 'https://thecolony.ai/oauth/par']);
        $provider = $this->providerWithHistory([
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($disc)),
            new Response(201, ['Content-Type' => 'application/json'], (string) json_encode(['request_uri' => 'urn:colony:par:perCall'])),
        ], $history, ['clientSecret' => 'secret']); // usePar defaults to false

        $url = $provider->getAuthorizationUrl(['use_par' => true]);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('urn:colony:par:perCall', $q['request_uri']);
        self::assertArrayNotHasKey('use_par', $q);
    }

    #[Test]
    public function par_raises_when_the_idp_does_not_advertise_it(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['usePar' => true]);
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('PAR endpoint');
        $provider->getAuthorizationUrl();
    }
}
