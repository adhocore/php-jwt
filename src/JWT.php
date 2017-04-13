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
class JWT
{
    const ERROR_KEY_EMPTY        = 1;
    const ERROR_ALGO_UNSUPPORTED = 2;
    const ERROR_ALGO_MISSING     = 3;
    const ERROR_INVALID_MAXAGE   = 4;
    const ERROR_JSON_FAILED      = 5;
    const ERROR_TOKEN_INVALID    = 6;
    const ERROR_TOKEN_EXPIRED    = 7;
    const ERROR_TOKEN_NOT_NOW    = 8;
    const ERROR_SIGNATURE_FAILED = 9;

    protected $algos = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
    ];

    /**
     * The signature key.
     *
     * @var string
     */
    protected $key;

    /**
     * Use setTestTimestamp() to set custom value for time(). Useful for testability.
     *
     * @var integer|null
     */
    protected $timestamp = null;

    /**
     * The JWT signing algorithm. Defaults to HS256.
     *
     * @var string
     */
    protected $algo = 'HS256';

    /**
     * The JWT TTL in seconds. Defaults to 1 hour.
     *
     * @var integer
     */
    protected $maxAge = 3600;

    /**
     * Grace period in seconds to allow for clock skew. Defaults to 0 seconds.
     *
     * @var integer
     */
    protected $leeway = 0;

    public function __construct(string $key, string $algo = 'HS256', int $maxAge = 3600, int $leeway = 0)
    {
        // @codeCoverageIgnoreStart
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
        // @codeCoverageIgnoreEnd

        $this->key    = $key;
        $this->algo   = $algo;
        $this->maxAge = $maxAge;
        $this->leeway = $leeway;
    }

    // @codeCoverageIgnoreStart
    public function encode(array $payload, array $header = []) : string
    {
        return $this->generate($payload, $header);
    }

    public function decode(string $token) : array
    {
        return $this->parse($token);
    }
    // @codeCoverageIgnoreEnd

    public function setTestTimestamp(int $timestamp = null) : JWT
    {
        $this->timestamp = $timestamp;

        return $this;
    }

    public function generate(array $payload, array $header = []) : string
    {
        $header = ['typ' => 'JWT', 'alg' => $this->algo] + $header;

        if (!isset($payload['iat']) && !isset($payload['exp'])) {
            $payload['exp'] = ($this->timestamp ?? time()) + $this->maxAge;
        }

        $header  = $this->urlSafeEncode($header);
        $payload = $this->urlSafeEncode($payload);

        $signature = hash_hmac($this->algos[$this->algo], $header . '.' . $payload, $this->key, true);
        $signature = $this->urlSafeEncode($signature);

        return $header . '.' . $payload . '.' . $signature;
    }

    public function parse(string $token) : array
    {
        if (substr_count($token, '.') < 2) {
            throw new \InvalidArgumentException('Invalid token: Incomplete segments', static::ERROR_TOKEN_INVALID);
        }

        $token  = explode('.', $token, 3);
        $header = $this->urlSafeDecode($token[0]);

        // Validate header.
        if (empty($header->alg)) {
            throw new \InvalidArgumentException('Invalid token: Missing header algo', static::ERROR_ALGO_MISSING);
        }
        if (!isset($this->algos[$header->alg])) {
            throw new \InvalidArgumentException('Invalid token: Unsupported header algo', static::ERROR_ALGO_UNSUPPORTED);
        }

        // Validate signature.
        $signature = hash_hmac($this->algos[$header->alg], $token[0] . '.' . $token[1], $this->key, true);
        if (!hash_equals($this->urlSafeEncode($signature), $token[2])) {
            throw new \InvalidArgumentException('Invalid token: Signature failed', static::ERROR_SIGNATURE_FAILED);
        }

        $payload = $this->urlSafeDecode($token[1]);

        // Validate expiry.
        $timestamp = $this->timestamp ?? time();
        if (isset($payload->exp) && $timestamp >= ($payload->exp + $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Expired', static::ERROR_TOKEN_EXPIRED);
        }

        if (isset($payload->iat) && $timestamp >= ($payload->iat + $this->maxAge - $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Expired', static::ERROR_TOKEN_EXPIRED);
        }

        if (isset($payload->nbf) && $timestamp <= ($payload->nbf - $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Cannot accept now', static::ERROR_TOKEN_NOT_NOW);
        }

        return (array) $payload;
    }

    protected function urlSafeEncode($data) : string
    {
        if (is_array($data)) {
            $data = json_encode($data, JSON_UNESCAPED_SLASHES);
            $this->throwIfJsonError();
        }

        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    protected function urlSafeDecode(string $data)
    {
        $data = json_decode(base64_decode(strtr($data, '-_', '+/')));
        $this->throwIfJsonError();

        return $data;
    }

    protected function throwIfJsonError()
    {
        if (JSON_ERROR_NONE === $error = json_last_error()) {
            return;
        }

        $errorMessage = [
            JSON_ERROR_STATE_MISMATCH => 'Underflow or the modes mismatch',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters, possibly incorrectly encoded',
        ][$error] ?? 'Unknown error';

        throw new \InvalidArgumentException('JSON failed: ' . $errorMessage, static::ERROR_JSON_FAILED);
    }
}
