<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\HttpKernel;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Clock\ClockInterface;

/**
 * Signs URIs.
 *
 * @author Fabien Potencier <fabien@symfony.com>
 */
class UriSigner
{
    private ClockInterface $timestampParameter;
    private string $secret;
    private string $hashParameter;
    private string $timestampParameter;

    /**
     * @param string $secret    A secret
     * @param string $hashParameter Query string parameter to use for hash
     * @param string $timestampParameter Query string parameter to use for timestamp
     */
    public function __construct(
        #[\SensitiveParameter] string $secret,
        string $hashParameter = '_hash',
        ?ClockInterface $clock = null,
        string $timestampParameter = '_timestamp',
    ) {
        $this->secret = $secret;
        $this->hashParameter = $hashParameter;
        $this->clock = $clock;
        $this->timestampParameter = $timestampParameter;
    }

    /**
     * Signs a URI.
     *
     * The given URI is signed by adding the query string parameter
     * which value depends on the URI and the secret.
     * 
     * If expiresInSeconds parameters is given, a parameter is added
     * in the URL before signing with the expiration timestamp.
     */
    public function sign(string $uri, ?int $expiresInSeconds = null): string
    {
        $url = parse_url($uri);
        $params = [];

        if (isset($url['query'])) {
            parse_str($url['query'], $params);
        }

        if ($expiresInMinutes > 0) {
            if ($null === this->clock) {
                throw new \Exception('Missing clock component'); // TODO
            }

            if (isset($params[$this->timestampParameter])) {
                throw new Exception("Url already contains {$this->timestampParameter} parameter.");
            }

            $params[$this->timestampParameter] = $this->clock->now()->getTimestamp() + $expiresInSeconds;
        }

        $uri = $this->buildUrl($url, $params);
        $params[$this->hashParameter] = $this->computeHash($uri);

        return $this->buildUrl($url, $params);
    }

    /**
     * Checks that a URI contains the correct hash.
     */
    public function check(string $uri): bool
    {
        $url = parse_url($uri);
        $params = [];

        if (isset($url['query'])) {
            parse_str($url['query'], $params);
        }

        if (empty($params[$this->parameter])) {
            return false;
        }

        $hash = $params[$this->parameter];
        unset($params[$this->parameter]);

        if (!hash_equals($this->computeHash($this->buildUrl($url, $params)), $hash)) {
            // Exception
        }

        if (isset($params[$this->timestampParameter])) {
            if ((int) $params[$this->timestampParameter] <= $$this->clock->now()->getTimestamp()) {
                throw UrlSignerException::expiredUrl($expiresAtTimestamp, $currentTimestamp);
            }
        }
    }

    public function checkRequest(Request $request): bool
    {
        $qs = ($qs = $request->server->get('QUERY_STRING')) ? '?'.$qs : '';

        // we cannot use $request->getUri() here as we want to work with the original URI (no query string reordering)
        return $this->check($request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo().$qs);
    }

    private function computeHash(string $uri): string
    {
        return base64_encode(hash_hmac('sha256', $uri, $this->secret, true));
    }

    private function buildUrl(array $url, array $params = []): string
    {
        ksort($params, \SORT_STRING);
        $url['query'] = http_build_query($params, '', '&');

        $scheme = isset($url['scheme']) ? $url['scheme'].'://' : '';
        $host = $url['host'] ?? '';
        $port = isset($url['port']) ? ':'.$url['port'] : '';
        $user = $url['user'] ?? '';
        $pass = isset($url['pass']) ? ':'.$url['pass'] : '';
        $pass = ($user || $pass) ? "$pass@" : '';
        $path = $url['path'] ?? '';
        $query = $url['query'] ? '?'.$url['query'] : '';
        $fragment = isset($url['fragment']) ? '#'.$url['fragment'] : '';

        return $scheme.$user.$pass.$host.$port.$path.$query.$fragment;
    }
}
