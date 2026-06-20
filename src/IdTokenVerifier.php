<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use TheColony\OAuth2\Exception\ColonyOidcException;

/**
 * Verifies an OIDC id_token's RS256 signature against a JWKS and checks its core
 * claims (iss / aud / exp / nonce / sub). Crypto is delegated to
 * web-token/jwt-library — the maintained library Symfony's own OidcTokenHandler
 * uses — rather than a hand-rolled JWKS→PEM path.
 */
final class IdTokenVerifier
{
    private const LEEWAY_SECONDS = 60;

    private JWSVerifier $verifier;
    private CompactSerializer $serializer;

    public function __construct()
    {
        $this->verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * @param string $jwksJson  Raw JWKS document (the issuer's signing keys).
     * @return array<string,mixed> the verified claim set
     */
    public function verify(
        string $idToken,
        string $jwksJson,
        string $issuer,
        string $clientId,
        string $expectedNonce,
        ?int $now = null,
    ): array {
        $now ??= time();

        try {
            $jws = $this->serializer->unserialize($idToken);
        } catch (\Throwable $e) {
            throw new ColonyOidcException('unparseable id_token', 0, $e);
        }

        $header = $jws->getSignature(0)->getProtectedHeader();
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new ColonyOidcException('unsupported id_token alg (expected RS256)');
        }

        $keySet = $this->keySet($jwksJson);
        if (!$this->verifier->verifyWithKeySet($jws, $keySet, 0)) {
            throw new ColonyOidcException('id_token signature does not verify');
        }

        /** @var array<string,mixed> $claims */
        $claims = json_decode((string) $jws->getPayload(), true);
        if (!is_array($claims)) {
            throw new ColonyOidcException('id_token payload is not a JSON object');
        }

        if (($claims['iss'] ?? null) !== $issuer) {
            throw new ColonyOidcException('id_token issuer mismatch');
        }
        $aud = $claims['aud'] ?? null;
        $audOk = is_array($aud) ? in_array($clientId, $aud, true) : $aud === $clientId;
        if (!$audOk) {
            throw new ColonyOidcException('id_token audience mismatch');
        }
        if (!isset($claims['exp']) || $now > ((int) $claims['exp'] + self::LEEWAY_SECONDS)) {
            throw new ColonyOidcException('id_token expired');
        }
        if (($claims['nonce'] ?? null) !== $expectedNonce) {
            throw new ColonyOidcException('id_token nonce mismatch');
        }
        if (!isset($claims['sub']) || $claims['sub'] === '') {
            throw new ColonyOidcException('id_token missing sub');
        }

        return $claims;
    }

    private function keySet(string $jwksJson): JWKSet
    {
        $data = json_decode($jwksJson, true);
        if (!is_array($data) || !isset($data['keys'])) {
            throw new ColonyOidcException('invalid JWKS document');
        }

        return JWKSet::createFromKeyData($data);
    }
}
