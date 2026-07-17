<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Tests;

use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;
use TheColony\OAuth2\Exception\ColonyOidcException;
use TheColony\OAuth2\IdTokenVerifier;

final class IdTokenVerifierTest extends TestCase
{
    private OidcTestKit $kit;
    private IdTokenVerifier $verifier;

    protected function setUp(): void
    {
        $this->kit = new OidcTestKit();
        $this->verifier = new IdTokenVerifier();
    }

    /** @param array<string,mixed> $claimOverrides */
    private function verify(array $claimOverrides = [], ?int $now = null): array
    {
        $token = $this->kit->idToken(OidcTestKit::claims($claimOverrides));

        return $this->verifier->verify(
            $token,
            $this->kit->jwksJson(),
            'https://thecolony.ai',
            'colony_client_abc',
            'nonce-xyz',
            $now,
        );
    }

    #[Test]
    public function it_verifies_a_well_formed_token(): void
    {
        $claims = $this->verify();
        self::assertSame('colony-sub-123', $claims['sub']);
        self::assertSame('agent@thecolony.cc', $claims['email']);
    }

    #[Test]
    public function it_rejects_an_unparseable_token(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->verifier->verify('not-a-jwt', $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', 'nonce-xyz');
    }

    #[Test]
    public function it_rejects_a_token_signed_by_another_key(): void
    {
        $attacker = new OidcTestKit();
        $token = $attacker->idToken(OidcTestKit::claims());
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('signature');
        // verify against OUR jwks, not the attacker's
        $this->verifier->verify($token, $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', 'nonce-xyz');
    }

    #[Test]
    public function it_rejects_a_non_rs256_alg(): void
    {
        // Build with a deliberately wrong header alg via the kit (HS-like label not allowed).
        $token = $this->kit->idToken(OidcTestKit::claims());
        // Tamper the header segment to claim alg=none.
        [$h, $p, $s] = explode('.', $token);
        $tampered = rtrim(strtr(base64_encode('{"alg":"none"}'), '+/', '-_'), '=') . ".$p.$s";
        $this->expectException(ColonyOidcException::class);
        $this->verifier->verify($tampered, $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', 'nonce-xyz');
    }

    #[Test]
    public function it_rejects_issuer_mismatch(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('issuer');
        $this->verify(['iss' => 'https://evil.example']);
    }

    #[Test]
    public function it_rejects_audience_mismatch(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('audience');
        $this->verify(['aud' => 'someone-else']);
    }

    #[Test]
    public function it_accepts_audience_as_array_containing_client(): void
    {
        $claims = $this->verify(['aud' => ['colony_client_abc', 'other']]);
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_azp_naming_another_client(): void
    {
        // OIDC Core §3.1.3.7(5): a present azp MUST be this client, even if aud lists us.
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('azp');
        $this->verify(['aud' => ['colony_client_abc', 'attacker'], 'azp' => 'attacker']);
    }

    #[Test]
    public function it_accepts_azp_that_matches_the_client(): void
    {
        $claims = $this->verify(['aud' => ['colony_client_abc', 'other'], 'azp' => 'colony_client_abc']);
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_expired_token(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('expired');
        $this->verify(['exp' => 1000], now: 4102444800);
    }

    #[Test]
    public function it_allows_small_clock_skew(): void
    {
        // exp 30s in the past, now within the 60s leeway → still valid
        $claims = $this->verify(['exp' => 1_000_000], now: 1_000_030);
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_a_not_yet_valid_token(): void
    {
        // nbf 600s ahead of `now`, beyond the 60s leeway → not yet valid
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('not yet valid');
        $this->verify(['nbf' => 1_700_000_600], now: 1_700_000_000);
    }

    #[Test]
    public function it_allows_nbf_within_clock_skew(): void
    {
        // nbf 30s ahead of `now` but inside the 60s leeway → still valid
        $claims = $this->verify(['nbf' => 1_700_000_030], now: 1_700_000_000);
        self::assertSame('colony-sub-123', $claims['sub']);
    }

    #[Test]
    public function it_rejects_nonce_mismatch(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('nonce');
        $this->verify(['nonce' => 'different']);
    }

    #[Test]
    public function null_nonce_skips_the_check_for_a_nonceless_token(): void
    {
        // RFC 8693 token-exchange id_tokens carry no nonce.
        $claims = OidcTestKit::claims();
        unset($claims['nonce']);
        $token = $this->kit->idToken($claims);

        $verified = $this->verifier->verify($token, $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', null);
        self::assertSame('colony-sub-123', $verified['sub']);
    }

    #[Test]
    public function null_nonce_ignores_a_present_nonce(): void
    {
        $token = $this->kit->idToken(OidcTestKit::claims(['nonce' => 'whatever']));

        $verified = $this->verifier->verify($token, $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', null);
        self::assertSame('colony-sub-123', $verified['sub']);
    }

    #[Test]
    public function it_rejects_missing_sub(): void
    {
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('sub');
        $this->verify(['sub' => '']);
    }

    #[Test]
    public function it_rejects_a_non_object_payload(): void
    {
        $token = $this->kit->idTokenRaw(json_encode('just-a-string'));
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('JSON object');
        $this->verifier->verify($token, $this->kit->jwksJson(), 'https://thecolony.ai', 'colony_client_abc', 'nonce-xyz');
    }

    #[Test]
    public function it_rejects_invalid_jwks(): void
    {
        $token = $this->kit->idToken(OidcTestKit::claims());
        $this->expectException(ColonyOidcException::class);
        $this->expectExceptionMessage('JWKS');
        $this->verifier->verify($token, '{"not":"a keyset"}', 'https://thecolony.ai', 'colony_client_abc', 'nonce-xyz');
    }
}
