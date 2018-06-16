<?php

namespace Ahc\Jwt;

/**
 * JSON Web Token (JWT) implementation in PHP7.
 *
 * @author   Jitendra Adhikari <jiten.adhikary@gmail.com>
 * @license  MIT
 *
 * @link     https://github.com/adhocore/jwt
 */
trait ValidatesJWT
{
    /**
     * Throw up if input parameters invalid.
     *
     * @codeCoverageIgnore
     */
    protected function validateConfig($key, string $algo, int $maxAge, int $leeway)
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Signing key cannot be empty', static::ERROR_KEY_EMPTY);
        }

        if (!isset($this->algos[$algo])) {
            throw new \InvalidArgumentException('Unsupported algo ' . $algo, static::ERROR_ALGO_UNSUPPORTED);
        }

        if ($maxAge < 1) {
            throw new \InvalidArgumentException('Invalid maxAge: Should be greater than 0', static::ERROR_INVALID_MAXAGE);
        }

        if ($leeway < 0 || $leeway > 120) {
            throw new \InvalidArgumentException('Invalid leeway: Should be between 0-120', static::ERROR_INVALID_LEEWAY);
        }
    }

    /**
     * Throw up if header invalid.
     */
    protected function validateHeader(array $header)
    {
        if (empty($header['alg'])) {
            throw new \InvalidArgumentException('Invalid token: Missing header algo', static::ERROR_ALGO_MISSING);
        }
        if (empty($this->algos[$header['alg']])) {
            throw new \InvalidArgumentException('Invalid token: Unsupported header algo', static::ERROR_ALGO_UNSUPPORTED);
        }

        $this->validateKid($header);
    }

    /**
     * Throw up if kid exists and invalid.
     */
    protected function validateKid(array $header)
    {
        if (!isset($header['kid'])) {
            return;
        }
        if (empty($this->keys[$header['kid']])) {
            throw new \InvalidArgumentException('Invalid token: Unknown key ID', static::ERROR_KID_UNKNOWN);
        }

        $this->key = $this->keys[$header['kid']];
    }

    /**
     * Throw up if timestamp claims like iat, exp, nbf are invalid.
     */
    protected function validateTimestamps(array $payload)
    {
        $timestamp = $this->timestamp ?? \time();
        if (isset($payload['exp']) && $timestamp >= ($payload['exp'] + $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Expired', static::ERROR_TOKEN_EXPIRED);
        }

        if (isset($payload['iat']) && $timestamp >= ($payload['iat'] + $this->maxAge - $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Expired', static::ERROR_TOKEN_EXPIRED);
        }

        if (isset($payload['nbf']) && $timestamp <= ($payload['nbf'] - $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Cannot accept now', static::ERROR_TOKEN_NOT_NOW);
        }
    }

    /**
     * Throw up if key is not resource or file path to private key.
     */
    protected function validateKey()
    {
        if (\is_string($this->key)) {
            if (!\is_file($this->key)) {
                throw new \InvalidArgumentException('Invalid key: Should be file path of private key', static::ERROR_KEY_INVALID);
            }

            $this->key = \openssl_get_privatekey('file://' . $this->key, $this->passphrase ?? '');
        }

        if (!\is_resource($this->key)) {
            throw new \InvalidArgumentException('Invalid key: Should be resource of private key', static::ERROR_KEY_INVALID);
        }
    }

    /**
     * Throw up if last json_encode/decode was a failure.
     */
    protected function validateLastJson()
    {
        if (JSON_ERROR_NONE === \json_last_error()) {
            return;
        }

        throw new \InvalidArgumentException('JSON failed: ' . \json_last_error_msg(), static::ERROR_JSON_FAILED);
    }
}
