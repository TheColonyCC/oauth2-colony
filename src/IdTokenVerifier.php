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

    /** OIDC Back-Channel Logout 1.0 event identifier (§2.4). */
    public const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private JWSVerifier $verifier;
    private CompactSerializer $serializer;

    public function __construct()
    {
        $this->verifier = new JWSVerifier(new AlgorithmManager([new RS256()]));
        $this->serializer = new CompactSerializer();
    }

    /**
     * @param string      $jwksJson      Raw JWKS document (the issuer's signing keys).
     * @param string|null $expectedNonce the nonce bound to the auth request; `null` skips
     *                                   the nonce check (e.g. an RFC 8693 token-exchange
     *                                   id_token, which carries no nonce)
     * @return array<string,mixed> the verified claim set
     */
    public function verify(
        string $idToken,
        string $jwksJson,
        string $issuer,
        string $clientId,
        ?string $expectedNonce = null,
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
        // OIDC Core §3.1.3.7(5): when the `azp` (authorized party) claim is present it
        // identifies the party the token was issued FOR and MUST be this client — even
        // when `aud` also lists other audiences. The Colony IdP issues single-audience
        // tokens with no azp, so this only ever rejects a token deliberately authorized
        // to a different client (a cross-client replay against this relying party).
        if (isset($claims['azp']) && $claims['azp'] !== $clientId) {
            throw new ColonyOidcException('id_token azp mismatch');
        }
        if (!isset($claims['exp']) || $now > ((int) $claims['exp'] + self::LEEWAY_SECONDS)) {
            throw new ColonyOidcException('id_token expired');
        }
        if ($expectedNonce !== null && ($claims['nonce'] ?? null) !== $expectedNonce) {
            throw new ColonyOidcException('id_token nonce mismatch');
        }
        if (!isset($claims['sub']) || $claims['sub'] === '') {
            throw new ColonyOidcException('id_token missing sub');
        }

        return $claims;
    }

    /**
     * Verify a back-channel `logout_token` (OIDC Back-Channel Logout 1.0 §2.4/§2.6).
     *
     * Different rules from an id_token: `iat` is required, `exp` is optional (checked
     * when present), a `nonce` MUST be absent, there must be a `sub` and/or `sid`, and an
     * `events` object must carry the back-channel-logout member.
     *
     * @param string $jwksJson Raw JWKS document (the issuer's signing keys).
     * @return array<string,mixed> the validated claim set
     */
    public function verifyLogoutToken(
        string $logoutToken,
        string $jwksJson,
        string $issuer,
        string $clientId,
        ?int $now = null,
    ): array {
        $now ??= time();

        try {
            $jws = $this->serializer->unserialize($logoutToken);
        } catch (\Throwable $e) {
            throw new ColonyOidcException('unparseable logout_token', 0, $e);
        }

        $header = $jws->getSignature(0)->getProtectedHeader();
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new ColonyOidcException('unsupported logout_token alg (expected RS256)');
        }

        if (!$this->verifier->verifyWithKeySet($jws, $this->keySet($jwksJson), 0)) {
            throw new ColonyOidcException('logout_token signature does not verify');
        }

        /** @var array<string,mixed> $claims */
        $claims = json_decode((string) $jws->getPayload(), true);
        if (!is_array($claims)) {
            throw new ColonyOidcException('logout_token payload is not a JSON object');
        }

        if (($claims['iss'] ?? null) !== $issuer) {
            throw new ColonyOidcException('logout_token issuer mismatch');
        }
        $aud = $claims['aud'] ?? null;
        $audOk = is_array($aud) ? in_array($clientId, $aud, true) : $aud === $clientId;
        if (!$audOk) {
            throw new ColonyOidcException('logout_token audience mismatch');
        }
        if (!isset($claims['iat'])) {
            throw new ColonyOidcException('logout_token missing iat');
        }
        if (isset($claims['exp']) && $now > ((int) $claims['exp'] + self::LEEWAY_SECONDS)) {
            throw new ColonyOidcException('logout_token expired');
        }
        // §2.4: a logout token MUST NOT contain a nonce (that would be an id_token).
        if (array_key_exists('nonce', $claims)) {
            throw new ColonyOidcException('logout_token must not contain a nonce');
        }
        // §2.4: MUST identify the subject/session to log out via sub and/or sid.
        $hasSub = isset($claims['sub']) && $claims['sub'] !== '';
        $hasSid = isset($claims['sid']) && $claims['sid'] !== '';
        if (!$hasSub && !$hasSid) {
            throw new ColonyOidcException('logout_token must contain a sub and/or sid');
        }
        // §2.4: the events claim asserts this is a back-channel logout event.
        $events = $claims['events'] ?? null;
        if (!is_array($events) || !array_key_exists(self::BACKCHANNEL_LOGOUT_EVENT, $events)) {
            throw new ColonyOidcException('logout_token events is missing the back-channel-logout member');
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
