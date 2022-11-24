<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel\Exception;

class UrlSignerSignException extends \LogicException
{
    public static function missingClockComponent()
    {
        return new self('Clock component is missing');
    }

    public static function timestampParameterAlreadyPresent()
    {
        return new self('Timestamp parameter is already present');
    }

}
