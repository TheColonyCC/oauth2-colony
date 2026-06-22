<?php

declare(strict_types=1);

namespace TheColony\OAuth2\Exception;

/**
 * A silent (`prompt=none`) authorization attempt failed because the user must
 * grant consent — the IdP returned `error=consent_required`. Fall back to an
 * interactive login so consent can be collected. Raised by
 * {@see \TheColony\OAuth2\ColonyProvider::raiseForCallbackError()}.
 */
class ColonyConsentRequiredException extends ColonyOidcException
{
}
