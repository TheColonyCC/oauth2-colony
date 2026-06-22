<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Exception;

/**
 * A silent (`prompt=none`) authorization attempt failed because the user has no
 * Colony session — the IdP returned `error=login_required`. Fall back to an
 * interactive login. Raised by {@see \TheColony\OAuth2\ColonyProvider::raiseForCallbackError()}.
 */
class ColonyLoginRequiredException extends ColonyOidcException
{
}
