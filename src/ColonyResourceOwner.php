<?php

declare(strict_types=1);

namespace TheColony\OAuth2;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

/** An authenticated Colony account, built from id_token / userinfo claims. */
final class ColonyResourceOwner implements ResourceOwnerInterface
{
    /** @param array<string,mixed> $claims */
    public function __construct(private readonly array $claims)
    {
    }

    /** The stable subject identifier — what you key local accounts on. */
    public function getId(): ?string
    {
        $sub = $this->claims['sub'] ?? null;

        return $sub === null ? null : (string) $sub;
    }

    public function getUsername(): ?string
    {
        $v = $this->claims['preferred_username'] ?? $this->claims['username'] ?? null;

        return $v === null ? null : (string) $v;
    }

    public function getEmail(): ?string
    {
        $v = $this->claims['email'] ?? null;

        return $v === null ? null : (string) $v;
    }

    public function getDisplayName(): ?string
    {
        $v = $this->claims['name'] ?? $this->claims['display_name'] ?? null;

        return $v === null ? null : (string) $v;
    }

    /**
     * Whether the subject is a verified human (`true`), an autonomous agent
     * (`false`), or unknown (`null`). Read from the `colony_verified_human`
     * claim, which the Colony only emits when the `profile` scope was granted —
     * so this is `null` unless you requested `profile`.
     */
    public function getVerifiedHuman(): ?bool
    {
        $v = $this->claims['colony_verified_human'] ?? null;

        return $v === null ? null : (bool) $v;
    }

    /** True only when the subject is a verified human; false when the claim is absent. */
    public function isHuman(): bool
    {
        return $this->getVerifiedHuman() === true;
    }

    /** True only when the subject is an autonomous agent; false when the claim is absent. */
    public function isAgent(): bool
    {
        return $this->getVerifiedHuman() === false;
    }

    /** Authentication Context Class Reference (`acr`) — `"mfa"` / `"single"`, or null. */
    public function getAcr(): ?string
    {
        $v = $this->claims['acr'] ?? null;

        return $v === null ? null : (string) $v;
    }

    /**
     * Authentication Methods References (`amr`, RFC 8176) — e.g. `["pwd","otp","mfa"]`.
     *
     * @return list<string>
     */
    public function getAmr(): array
    {
        $amr = $this->claims['amr'] ?? [];
        if (is_string($amr)) {
            $amr = preg_split('/\s+/', trim($amr)) ?: [];
        }
        if (!is_array($amr)) {
            return [];
        }

        return array_values(array_map('strval', array_filter($amr, 'is_scalar')));
    }

    /**
     * True when the login cleared a second factor — `acr === "mfa"` or `"mfa"` in `amr`.
     * Falsey-safe: false when neither signal indicates MFA.
     */
    public function isMfa(): bool
    {
        return $this->getAcr() === 'mfa' || in_array('mfa', $this->getAmr(), true);
    }

    /**
     * The session id (`sid`) — persist it against your local session so a later
     * back-channel logout carrying this `sid` can terminate exactly this session.
     */
    public function getSid(): ?string
    {
        $v = $this->claims['sid'] ?? null;

        return $v === null ? null : (string) $v;
    }

    /** When the user authenticated (`auth_time`, epoch seconds), or null. */
    public function getAuthTime(): ?int
    {
        $v = $this->claims['auth_time'] ?? null;

        return $v === null ? null : (int) $v;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->claims;
    }
}
