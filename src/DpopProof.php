<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * DPoP proof factory (RFC 9449) — mints the `dpop+jwt` proof JWTs that
 * sender-constrain the Colony's tokens to a key this client holds.
 *
 * A proof is a compact JWS whose protected header carries `typ: dpop+jwt` and the
 * **public** proof key (`jwk`), and whose claims bind it to one request: `htm`
 * (method) + `htu` (URL) + a fresh `jti` + `iat`, optionally `ath`
 * (base64url(sha256(access_token))) at a protected resource and a server-issued
 * `nonce` (RFC 9449 §8). The key never leaves the client; the IdP records its
 * RFC 7638 thumbprint ({@see thumbprint()}) as the token's `cnf.jkt`.
 */
final class DpopProof
{
    /** Proof signing algorithms we support — asymmetric only, EC first (the DPoP default). */
    public const ALGS = ['ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512'];

    /** @var array<string,mixed> the public JWK embedded in every proof header */
    private array $publicJwk;
    private JWSBuilder $builder;
    private CompactSerializer $serializer;

    public function __construct(private JWK $key, private string $alg = 'ES256')
    {
        if (!in_array($alg, self::ALGS, true)) {
            throw new \InvalidArgumentException('dpopAlg must be one of: ' . implode(', ', self::ALGS));
        }
        /** @var class-string $algClass */
        $algClass = 'Jose\\Component\\Signature\\Algorithm\\' . $alg;
        $this->builder = new JWSBuilder(new AlgorithmManager([new $algClass()]));
        $this->serializer = new CompactSerializer();
        $this->publicJwk = $key->toPublic()->all();
    }

    /**
     * Build a proof key from an option: an existing web-token JWK, a PEM string, a path
     * to a PEM file, or `null` to generate a fresh key for the algorithm.
     */
    public static function fromOption(mixed $key, string $alg = 'ES256'): self
    {
        if ($key instanceof JWK) {
            return new self($key, $alg);
        }
        if (is_string($key) && $key !== '') {
            $jwk = str_contains($key, '-----BEGIN')
                ? JWKFactory::createFromKey($key)
                : JWKFactory::createFromKeyFile($key);

            return new self($jwk, $alg);
        }

        return new self(self::generateKey($alg), $alg);
    }

    private static function generateKey(string $alg): JWK
    {
        return match ($alg) {
            'ES256' => JWKFactory::createECKey('P-256'),
            'ES384' => JWKFactory::createECKey('P-384'),
            'ES512' => JWKFactory::createECKey('P-521'),
            default => JWKFactory::createRSAKey(2048),
        };
    }

    /** RFC 7638 JWK thumbprint (SHA-256, base64url) — the value committed as `dpop_jkt`. */
    public function thumbprint(): string
    {
        return $this->key->toPublic()->thumbprint('sha256');
    }

    /**
     * Mint a proof for an `$htm` request to `$htu`. Pass `$accessToken` at a protected
     * resource to include `ath`, and `$nonce` to echo a server-issued DPoP nonce.
     */
    public function proof(string $htm, string $htu, ?string $accessToken = null, ?string $nonce = null): string
    {
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $htm,
            'htu' => $htu,
            'iat' => time(),
        ];
        if ($accessToken !== null) {
            $claims['ath'] = self::b64url(hash('sha256', $accessToken, true));
        }
        if ($nonce !== null && $nonce !== '') {
            $claims['nonce'] = $nonce;
        }
        $jws = $this->builder->create()
            ->withPayload((string) json_encode($claims))
            ->addSignature($this->key, ['typ' => 'dpop+jwt', 'alg' => $this->alg, 'jwk' => $this->publicJwk])
            ->build();

        return $this->serializer->serialize($jws, 0);
    }

    private static function b64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
