<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\ColonyProvider;
use TheColony\OAuth2\DpopProof;

/**
 * DPoP — sender-constrained tokens (RFC 9449), incl. the §10 dpop_jkt code
 * binding and the §8 use_dpop_nonce challenge-retry.
 */
final class DpopTest extends TestCase
{
    private const DISCOVERY = [
        'issuer' => 'https://thecolony.cc',
        'authorization_endpoint' => 'https://thecolony.cc/oauth/authorize',
        'token_endpoint' => 'https://thecolony.cc/oauth/token',
        'userinfo_endpoint' => 'https://thecolony.cc/oauth/userinfo',
        'jwks_uri' => 'https://thecolony.cc/.well-known/jwks.json',
    ];

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(self::DISCOVERY));
    }

    /** @param list<Response> $responses */
    private function provider(array $responses, array $options, array &$history): ColonyProvider
    {
        $stack = HandlerStack::create(new MockHandler($responses));
        $stack->push(Middleware::history($history));

        return new ColonyProvider(array_merge([
            'clientId' => 'colony_client_abc', 'clientSecret' => 'secret',
            'redirectUri' => 'https://app.example/cb',
        ], $options), ['httpClient' => new Client(['handler' => $stack])]);
    }

    /** @return array{0: array<string,mixed>, 1: array<string,mixed>} [header, claims] */
    private function decodeJwt(string $jwt): array
    {
        [$h, $p] = explode('.', $jwt);
        $dec = static fn (string $s): array => (array) json_decode(
            (string) base64_decode(strtr($s, '-_', '+/')), true);

        return [$dec($h), $dec($p)];
    }

    // ---- DpopProof unit ----

    #[Test]
    public function proof_has_dpop_header_and_bound_claims(): void
    {
        $jwk = JWKFactory::createECKey('P-256');
        $dpop = new DpopProof($jwk);
        [$header, $claims] = $this->decodeJwt($dpop->proof('POST', 'https://thecolony.cc/oauth/token'));

        self::assertSame('dpop+jwt', $header['typ']);
        self::assertSame('ES256', $header['alg']);
        self::assertSame(['kty', 'crv', 'x', 'y'], array_keys($header['jwk']));  // public only
        self::assertSame('POST', $claims['htm']);
        self::assertSame('https://thecolony.cc/oauth/token', $claims['htu']);
        self::assertArrayHasKey('jti', $claims);
        self::assertArrayHasKey('iat', $claims);
        self::assertArrayNotHasKey('ath', $claims);
    }

    #[Test]
    public function proof_includes_ath_and_nonce_when_given(): void
    {
        $dpop = new DpopProof(JWKFactory::createECKey('P-256'));
        [, $claims] = $this->decodeJwt($dpop->proof('GET', 'https://x/userinfo', 'the-access-token', 'srv-nonce'));
        $expectedAth = rtrim(strtr(base64_encode(hash('sha256', 'the-access-token', true)), '+/', '-_'), '=');
        self::assertSame($expectedAth, $claims['ath']);
        self::assertSame('srv-nonce', $claims['nonce']);
    }

    #[Test]
    public function thumbprint_is_rfc7638_and_matches_the_proof_key(): void
    {
        $jwk = JWKFactory::createECKey('P-256');
        self::assertSame($jwk->toPublic()->thumbprint('sha256'), (new DpopProof($jwk))->thumbprint());
    }

    #[Test]
    public function fromOption_generates_a_key_when_none_supplied(): void
    {
        $jkt = DpopProof::fromOption(null)->thumbprint();
        self::assertSame(43, strlen($jkt));  // base64url SHA-256, unpadded
    }

    // ---- authorization: dpop_jkt (RFC 9449 §10) ----

    #[Test]
    public function authorization_url_carries_dpop_jkt(): void
    {
        $history = [];
        $jwk = JWKFactory::createECKey('P-256');
        $provider = $this->provider([$this->discoveryResponse()], ['dpopKey' => $jwk], $history);
        parse_str((string) parse_url($provider->getAuthorizationUrl(), PHP_URL_QUERY), $q);
        self::assertSame((new DpopProof($jwk))->thumbprint(), $q['dpop_jkt']);
    }

    #[Test]
    public function authorization_url_has_no_dpop_jkt_without_dpop(): void
    {
        $history = [];
        $provider = $this->provider([$this->discoveryResponse()], [], $history);
        parse_str((string) parse_url($provider->getAuthorizationUrl(), PHP_URL_QUERY), $q);
        self::assertArrayNotHasKey('dpop_jkt', $q);
    }

    // ---- token endpoint: proof + nonce challenge-retry (§8) ----

    #[Test]
    public function token_request_carries_a_dpop_proof(): void
    {
        $history = [];
        $token = (string) json_encode(['access_token' => 'at', 'token_type' => 'DPoP']);
        $provider = $this->provider(
            [$this->discoveryResponse(), new Response(200, [], $token)],
            ['dpop' => true], $history);
        $result = $provider->getAccessToken('authorization_code', ['code' => 'abc']);

        self::assertSame('DPoP', $result->getValues()['token_type']);
        $proof = $history[1]['request']->getHeaderLine('DPoP');
        self::assertNotSame('', $proof);
        [$header, $claims] = $this->decodeJwt($proof);
        self::assertSame('dpop+jwt', $header['typ']);
        self::assertSame('POST', $claims['htm']);
        self::assertSame(self::DISCOVERY['token_endpoint'], $claims['htu']);
    }

    #[Test]
    public function token_request_answers_a_use_dpop_nonce_challenge(): void
    {
        $history = [];
        $challenge = new Response(400, ['DPoP-Nonce' => 'srv-nonce-1'],
            (string) json_encode(['error' => 'use_dpop_nonce']));
        $ok = new Response(200, [], (string) json_encode(['access_token' => 'at', 'token_type' => 'DPoP']));
        $provider = $this->provider(
            [$this->discoveryResponse(), $challenge, $ok], ['dpop' => true], $history);

        $result = $provider->getAccessToken('authorization_code', ['code' => 'abc']);
        self::assertSame('at', $result->getToken());

        // First attempt: no nonce. Retry: nonce embedded in a fresh proof.
        [, $first] = $this->decodeJwt($history[1]['request']->getHeaderLine('DPoP'));
        [, $retry] = $this->decodeJwt($history[2]['request']->getHeaderLine('DPoP'));
        self::assertArrayNotHasKey('nonce', $first);
        self::assertSame('srv-nonce-1', $retry['nonce']);
    }

    #[Test]
    public function exchange_token_carries_a_dpop_proof(): void
    {
        $history = [];
        $body = (string) json_encode(['access_token' => 'at', 'token_type' => 'DPoP', 'id_token' => 'x.y.z']);
        $provider = $this->provider(
            [$this->discoveryResponse(), new Response(200, [], $body)], ['dpop' => true], $history);
        $provider->exchangeToken('subject.jwt');
        self::assertNotSame('', $history[1]['request']->getHeaderLine('DPoP'));
    }

    // ---- userinfo: DPoP scheme + ath (§7.1) ----

    #[Test]
    public function userinfo_is_presented_under_the_dpop_scheme(): void
    {
        $history = [];
        $userinfo = new Response(200, [], (string) json_encode(['sub' => 'colony-sub-123']));
        $provider = $this->provider(
            [$this->discoveryResponse(), $userinfo], ['dpop' => true], $history);
        $owner = $provider->getResourceOwner(new \League\OAuth2\Client\Token\AccessToken([
            'access_token' => 'the-at', 'token_type' => 'DPoP']));

        self::assertSame('colony-sub-123', $owner->toArray()['sub']);
        $req = $history[1]['request'];
        self::assertSame('DPoP the-at', $req->getHeaderLine('Authorization'));
        [, $claims] = $this->decodeJwt($req->getHeaderLine('DPoP'));
        self::assertSame('GET', $claims['htm']);
        $expectedAth = rtrim(strtr(base64_encode(hash('sha256', 'the-at', true)), '+/', '-_'), '=');
        self::assertSame($expectedAth, $claims['ath']);
    }
}
