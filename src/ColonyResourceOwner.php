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

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->claims;
    }
}
