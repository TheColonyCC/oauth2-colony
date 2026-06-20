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

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        return $this->claims;
    }
}
