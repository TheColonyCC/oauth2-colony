<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\ColonyProvider;
use TheColony\OAuth2\Exception\ColonyOidcException;
use TheColony\OAuth2\IdTokenVerifier;

/**
 * RP-parity batch (PR A): JARM, Resource Indicators, and signed discovery
 * metadata (RFC 8414). DPoP ships separately.
 */
final class RpParityTest extends TestCase
{
    private const ISSUER = 'https://thecolony.cc';
    private const CLIENT = 'colony_client_abc';
    private const DISCOVERY = [
        'issuer' => self::ISSUER,
        'authorization_endpoint' => 'https://thecolony.cc/oauth/authorize',
        'token_endpoint' => 'https://thecolony.cc/oauth/token',
        'userinfo_endpoint' => 'https://thecolony.cc/oauth/userinfo',
        'jwks_uri' => 'https://thecolony.cc/.well-known/jwks.json',
    ];

    private OidcTestKit $kit;

    protected function setUp(): void
    {
        $this->kit = new OidcTestKit();
    }

    /** @param list<Response> $responses */
    private function provider(array $responses = [], array $options = []): ColonyProvider
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler($responses))]);

        return new ColonyProvider(array_merge([
            'clientId' => self::CLIENT,
            'clientSecret' => 'secret',
            'redirectUri' => 'https://app.example/auth/colony/callback',
        ], $options), ['httpClient' => $client]);
    }

    private function discoveryResponse(array $extra = []): Response
    {
        return new Response(200, [], (string) json_encode(array_merge(self::DISCOVERY, $extra)));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], $this->kit->jwksJson());
    }

    /** A signed JARM `response` JWT. */
    private function jarm(array $overrides = []): string
    {
        return $this->kit->idToken(array_merge([
            'iss' => self::ISSUER, 'aud' => self::CLIENT,
            'exp' => time() + 300, 'iat' => time(),
            'code' => 'the-code', 'state' => 'xyz',
        ], $overrides));
    }

    // ---- JARM: unit (IdTokenVerifier) ----

    #[Test]
    public function jarm_verify_returns_inner_params_without_envelope(): void
    {
        $out = (new IdTokenVerifier())->verifyJarm(
            $this->jarm(), $this->kit->jwksJson(), self::ISSUER, self::CLIENT, 'xyz');
        self::assertSame(['code' => 'the-code', 'state' => 'xyz'], $out);
    }

    #[Test]
    public function jarm_verify_rejects_wrong_issuer(): void
    {
        $this->expectException(ColonyOidcException::class);
        (new IdTokenVerifier())->verifyJarm(
            $this->jarm(['iss' => 'https://evil']), $this->kit->jwksJson(), self::ISSUER, self::CLIENT);
    }

    #[Test]
    public function jarm_verify_rejects_wrong_audience(): void
    {
        $this->expectException(ColonyOidcException::class);
        (new IdTokenVerifier())->verifyJarm(
            $this->jarm(['aud' => 'someone-else']), $this->kit->jwksJson(), self::ISSUER, self::CLIENT);
    }

    #[Test]
    public function jarm_verify_rejects_expired(): void
    {
        $this->expectException(ColonyOidcException::class);
        (new IdTokenVerifier())->verifyJarm(
            $this->jarm(['exp' => time() - 3600]), $this->kit->jwksJson(), self::ISSUER, self::CLIENT);
    }

    #[Test]
    public function jarm_verify_rejects_state_mismatch(): void
    {
        $this->expectException(ColonyOidcException::class);
        (new IdTokenVerifier())->verifyJarm(
            $this->jarm(['state' => 'a']), $this->kit->jwksJson(), self::ISSUER, self::CLIENT, 'b');
    }

    #[Test]
    public function jarm_verify_rejects_a_foreign_key(): void
    {
        $other = new OidcTestKit();
        $foreign = $other->idToken([
            'iss' => self::ISSUER, 'aud' => self::CLIENT, 'exp' => time() + 300, 'code' => 'x']);
        $this->expectException(ColonyOidcException::class);
        (new IdTokenVerifier())->verifyJarm($foreign, $this->kit->jwksJson(), self::ISSUER, self::CLIENT);
    }

    // ---- JARM: integration (provider resolves discovery + JWKS) ----

    #[Test]
    public function provider_parses_a_jarm_response(): void
    {
        $provider = $this->provider([$this->discoveryResponse(), $this->jwksResponse()]);
        $params = $provider->parseJarmResponse($this->jarm(), 'xyz');
        self::assertSame('the-code', $params['code']);
        self::assertSame('xyz', $params['state']);
    }

    // ---- signed discovery metadata (RFC 8414) ----

    private function signedMetadata(array $doc): string
    {
        return $this->kit->idToken(array_merge($doc, ['iss' => self::ISSUER, 'iat' => time()]));
    }

    #[Test]
    public function signed_metadata_values_take_precedence_over_tampered_json(): void
    {
        // The signed JWT covers the GOOD token_endpoint; the plain JSON is tampered.
        $sm = $this->signedMetadata(self::DISCOVERY);
        $tampered = ['token_endpoint' => 'https://evil.example/token', 'signed_metadata' => $sm];
        $provider = $this->provider(
            [$this->discoveryResponse($tampered), $this->jwksResponse()],
            ['verifySignedMetadata' => true]);
        self::assertSame(self::DISCOVERY['token_endpoint'], $provider->getOpenidConfiguration()['token_endpoint']);
    }

    #[Test]
    public function signed_metadata_missing_throws_when_required(): void
    {
        $provider = $this->provider([$this->discoveryResponse()], ['verifySignedMetadata' => true]);
        $this->expectException(ColonyOidcException::class);
        $provider->getOpenidConfiguration();
    }

    #[Test]
    public function signed_metadata_bad_signature_throws(): void
    {
        $foreign = (new OidcTestKit())->idToken(array_merge(self::DISCOVERY, ['iss' => self::ISSUER]));
        $provider = $this->provider(
            [$this->discoveryResponse(['signed_metadata' => $foreign]), $this->jwksResponse()],
            ['verifySignedMetadata' => true]);
        $this->expectException(ColonyOidcException::class);
        $provider->getOpenidConfiguration();
    }

    #[Test]
    public function signed_metadata_ignored_when_flag_off(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        self::assertSame(self::DISCOVERY['token_endpoint'], $provider->getOpenidConfiguration()['token_endpoint']);
    }

    // ---- Resource Indicators (RFC 8707) + response_mode passthrough ----

    #[Test]
    public function authorization_url_carries_resource_and_response_mode(): void
    {
        $provider = $this->provider([$this->discoveryResponse()]);
        $url = $provider->getAuthorizationUrl([
            'resource' => 'https://api.partner.example',
            'response_mode' => 'jwt',
        ]);
        parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
        self::assertSame('https://api.partner.example', $q['resource']);
        self::assertSame('jwt', $q['response_mode']);
    }

    #[Test]
    public function exchange_token_forwards_resource(): void
    {
        $tokenBody = (string) json_encode([
            'access_token' => 'at', 'token_type' => 'Bearer',
            'id_token' => $this->kit->idToken(OidcTestKit::claims(['nonce' => null])),
        ]);
        $history = [];
        $stack = HandlerStack::create(new MockHandler([$this->discoveryResponse(), new Response(200, [], $tokenBody)]));
        $stack->push(\GuzzleHttp\Middleware::history($history));
        $provider = new ColonyProvider(
            ['clientId' => self::CLIENT, 'clientSecret' => 'secret', 'redirectUri' => 'https://app.example/cb'],
            ['httpClient' => new Client(['handler' => $stack])]);
        $provider->exchangeToken('subject.jwt', options: ['resource' => 'https://api.partner.example']);
        $sent = (string) end($history)['request']->getBody();
        self::assertStringContainsString('resource=https%3A%2F%2Fapi.partner.example', $sent);
    }
}
