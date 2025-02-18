<?php

declare(strict_types=1);

/*
 * This file is part of the PHP-JWT package.
 *
 * (c) Jitendra Adhikari <jiten.adhikary@gmail.com>
 *     <https://github.com/adhocore>
 *
 * Licensed under MIT license.
 */

namespace Ahc\Jwt;

use OpenSSLAsymmetricKey;
use OpenSSLCertificate;
use OpenSSLCertificateSigningRequest;
use function is_resource;
use function is_string;
use function json_last_error;
use function json_last_error_msg;
use function openssl_get_privatekey;
use function substr;
use function time;
use const JSON_ERROR_NONE;
use const PHP_VERSION_ID;

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
            throw new JWTException('Signing key cannot be empty', static::ERROR_KEY_EMPTY);
        }

        if (!isset($this->algos[$algo])) {
            throw new JWTException('Unsupported algo ' . $algo, static::ERROR_ALGO_UNSUPPORTED);
        }

        if ($maxAge < 1) {
            throw new JWTException('Invalid maxAge: Should be greater than 0', static::ERROR_INVALID_MAXAGE);
        }

        if ($leeway < 0 || $leeway > 120) {
            throw new JWTException('Invalid leeway: Should be between 0-120', static::ERROR_INVALID_LEEWAY);
        }
    }

    /**
     * Throw up if header invalid.
     */
    protected function validateHeader(array $header)
    {
        if (empty($header['alg'])) {
            throw new JWTException('Invalid token: Missing header algo', static::ERROR_ALGO_MISSING);
        }
        if (empty($this->algos[$header['alg']])) {
            throw new JWTException('Invalid token: Unsupported header algo', static::ERROR_ALGO_UNSUPPORTED);
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
            throw new JWTException('Invalid token: Unknown key ID', static::ERROR_KID_UNKNOWN);
        }

        $this->key = $this->keys[$header['kid']];
    }

    /**
     * Throw up if timestamp claims like iat, exp, nbf are invalid.
     */
    protected function validateTimestamps(array $payload)
    {
        $timestamp = $this->timestamp ?: time();
        $checks    = [
            ['exp', $this->leeway /*          */ , static::ERROR_TOKEN_EXPIRED, 'Expired'],
            ['iat', $this->maxAge - $this->leeway, static::ERROR_TOKEN_EXPIRED, 'Expired'],
            ['nbf', -$this->leeway, static::ERROR_TOKEN_NOT_NOW, 'Not now'],
        ];

        foreach ($checks as list($key, $offset, $code, $error)) {
            if (isset($payload[$key])) {
                $offset += $payload[$key];
                $fail    = $key === 'nbf' ? $timestamp <= $offset : $timestamp >= $offset;

                if ($fail) {
                    throw new JWTException('Invalid token: ' . $error, $code);
                }
            }
        }
    }

    /**
     * Throw up if key is not resource or file path to private key.
     */
    protected function validateKey()
    {
        if (is_string($key = $this->key)) {
            if (strpos($key, 'file://') !== 0) {
                $key = 'file://' . $key;
            }

            $this->key = openssl_get_privatekey($key, $this->passphrase ?: '');
        }

        if (PHP_VERSION_ID < 80000 && !is_resource($this->key)) {
            throw new JWTException('Invalid key: Should be resource of private key', static::ERROR_KEY_INVALID);
        }

        if (PHP_VERSION_ID > 80000 && !(
            $this->key instanceof OpenSSLAsymmetricKey
            || $this->key instanceof OpenSSLCertificate
            || $this->key instanceof OpenSSLCertificateSigningRequest
        )) {
            throw new JWTException('Invalid key: Should be resource of private key', static::ERROR_KEY_INVALID);
        }
    }

    /**
     * Throw up if last json_encode/decode was a failure.
     */
    protected function validateLastJson()
    {
        if (JSON_ERROR_NONE === json_last_error()) {
            return;
        }

        throw new JWTException('JSON failed: ' . json_last_error_msg(), static::ERROR_JSON_FAILED);
    }
}
