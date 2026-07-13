<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * Test helpers: an in-process RSA signer + JWKS, so tests verify real RS256
 * tokens against a real key set without touching the network.
 */
final class OidcTestKit
{
    public readonly JWK $key;

    public function __construct(?JWK $key = null)
    {
        $this->key = $key ?? JWKFactory::createRSAKey(2048, ['alg' => 'RS256', 'use' => 'sig', 'kid' => 'test-1']);
    }

    /** The public JWKS document a verifier would fetch from jwks_uri. */
    public function jwksJson(): string
    {
        $public = $this->key->toPublic();

        return (string) json_encode(['keys' => [$public->jsonSerialize()]]);
    }

    /**
     * Mint a signed compact JWS id_token from the given claims.
     *
     * @param array<string,mixed> $claims
     */
    public function idToken(array $claims, string $alg = 'RS256'): string
    {
        $builder = new JWSBuilder(new AlgorithmManager([new RS256()]));
        $jws = $builder
            ->create()
            ->withPayload((string) json_encode($claims))
            ->addSignature($this->key, ['alg' => $alg])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /** Sign an arbitrary raw payload string (used to test non-object payloads). */
    public function idTokenRaw(string $payload): string
    {
        $builder = new JWSBuilder(new AlgorithmManager([new RS256()]));
        $jws = $builder
            ->create()
            ->withPayload($payload)
            ->addSignature($this->key, ['alg' => 'RS256'])
            ->build();

        return (new CompactSerializer())->serialize($jws, 0);
    }

    /**
     * Standard valid claim set; override any field via $overrides.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    public static function claims(array $overrides = []): array
    {
        return array_merge([
            'iss' => 'https://thecolony.ai',
            'sub' => 'colony-sub-123',
            'aud' => 'colony_client_abc',
            'exp' => 4102444800, // year 2100
            'iat' => 1700000000,
            'nonce' => 'nonce-xyz',
            'email' => 'agent@thecolony.cc',
            'preferred_username' => 'colonist-one',
            'name' => 'Colonist One',
        ], $overrides);
    }
}
