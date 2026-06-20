<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Exception;

/** Raised when an OIDC step (discovery, token exchange, id_token verification) fails. */
final class ColonyOidcException extends \RuntimeException
{
}
