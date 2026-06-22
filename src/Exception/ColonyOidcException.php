<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Exception;

/**
 * Raised when an OIDC step (discovery, token exchange, id_token / logout_token
 * verification) fails. Base class for the typed silent-SSO outcomes
 * {@see ColonyLoginRequiredException} / {@see ColonyConsentRequiredException}.
 */
class ColonyOidcException extends \RuntimeException
{
}
