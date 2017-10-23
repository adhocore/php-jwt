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
    const ERROR_KEY_EMPTY        = 10;
    const ERROR_KEY_INVALID      = 12;
    const ERROR_ALGO_UNSUPPORTED = 20;
    const ERROR_ALGO_MISSING     = 22;
    const ERROR_INVALID_MAXAGE   = 30;
    const ERROR_INVALID_LEEWAY   = 32;
    const ERROR_JSON_FAILED      = 40;
    const ERROR_TOKEN_INVALID    = 50;
    const ERROR_TOKEN_EXPIRED    = 52;
    const ERROR_TOKEN_NOT_NOW    = 54;
    const ERROR_SIGNATURE_FAILED = 60;

    /**
     * Supported Signing algorithms.
     *
     * @var array
     */
    protected $algos = [
        'HS256' => 'sha256',
        'HS384' => 'sha384',
        'HS512' => 'sha512',
        'RS256' => OPENSSL_ALGO_SHA256,
        'RS384' => OPENSSL_ALGO_SHA384,
        'RS512' => OPENSSL_ALGO_SHA512,
    ];

    /**
     * The signature key.
     *
     * @var string|resource
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

    /**
     * The passphrase for RSA signing (optional).
     *
     * @var string|null
     */
    protected $passphrase;

    /**
     * Constructor.
     *
     * @param string|resource $key    The signature key. For RS* it should be file path or resource of private key.
     * @param string          $algo   The algorithm to sign/verify the token.
     * @param integer         $maxAge The TTL of token to be used to determine expiry if `iat` claim is present.
     *                                This is also used to provide default `exp` claim in case it is missing.
     * @param integer         $leeway Leeway for clock skew. Shouldnot be more than 2 minutes (120s).
     * @param string          $pass   The passphrase (only for RS* algos).
     */
    public function __construct($key, string $algo = 'HS256', int $maxAge = 3600, int $leeway = 0, string $pass = null)
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

        $this->key        = $key;
        $this->algo       = $algo;
        $this->maxAge     = $maxAge;
        $this->leeway     = $leeway;
        $this->passphrase = $pass;
    }

    /**
     * Encode payload as JWT token.
     *
     * This method is alias of self::generate().
     *
     * @param  array  $payload
     * @param  array  $header  Extra header (if any) to append.
     *
     * @return string          URL safe JWT token.
     */
    public function encode(array $payload, array $header = []) : string
    {
        return $this->generate($payload, $header);
    }

    /**
     * Decode JWT token and return original payload.
     *
     * This method is alias of self::parse().
     *
     * @param  string $token
     *
     * @return array
     */
    public function decode(string $token) : array
    {
        return $this->parse($token);
    }

    /**
     * Spoof current timestamp for testing.
     *
     * @param integer|null $timestamp
     */
    public function setTestTimestamp(int $timestamp = null) : JWT
    {
        $this->timestamp = $timestamp;

        return $this;
    }

    /**
     * Generate JWT token.
     *
     * @param  array  $payload
     * @param  array  $header  Extra header (if any) to append.
     *
     * @return string          URL safe JWT token.
     */
    public function generate(array $payload, array $header = []) : string
    {
        $header = ['typ' => 'JWT', 'alg' => $this->algo] + $header;

        if (!isset($payload['iat']) && !isset($payload['exp'])) {
            $payload['exp'] = ($this->timestamp ?? time()) + $this->maxAge;
        }

        $header    = $this->urlSafeEncode($header);
        $payload   = $this->urlSafeEncode($payload);
        $signature = $this->urlSafeEncode($this->sign($header . '.' . $payload));

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Parse JWT token and return original payload.
     *
     * @param  string $token
     *
     * @return array
     *
     * @throws \InvalidArgumentException When JWT token is invalid or expired or signature can't be verified.
     */
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
        if (!$this->verify($token[0] . '.' . $token[1], $token[2])) {
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

        // Validate nbf claim.
        if (isset($payload->nbf) && $timestamp <= ($payload->nbf - $this->leeway)) {
            throw new \InvalidArgumentException('Invalid token: Cannot accept now', static::ERROR_TOKEN_NOT_NOW);
        }

        return (array) $payload;
    }

    /**
     * Sign the input with configured key and return the signature.
     *
     * @param  string $input
     *
     * @return string
     */
    protected function sign(string $input) : string
    {
        // HMAC SHA.
        if (substr($this->algo, 0, 2) === 'HS') {
            return hash_hmac($this->algos[$this->algo], $input, $this->key, true);
        }

        $this->throwIfKeyInvalid();

        openssl_sign($input, $signature, $this->key, $this->algos[$this->algo]);

        return $signature;
    }

    /**
     * Verify the signature of given input.
     *
     * @param  string $input
     * @param  string $signature
     *
     * @return bool
     *
     * @throws \InvalidArgumentException When key is invalid.
     */
    protected function verify(string $input, string $signature) : bool
    {
        $algo = $this->algos[$this->algo];

        // HMAC SHA.
        if (substr($this->algo, 0, 2) === 'HS') {
            return hash_equals($this->urlSafeEncode(hash_hmac($algo, $input, $this->key, true)), $signature);
        }

        $this->throwIfKeyInvalid();

        $pubKey = openssl_pkey_get_details($this->key)['key'];

        return openssl_verify($input, $this->urlSafeDecode($signature, false), $pubKey, $algo) === 1;
    }

    /**
     * Throw up if key is not resource or file path to private key.
     *
     * @throws \InvalidArgumentException
     */
    protected function throwIfKeyInvalid()
    {
        if (is_string($this->key)) {
            if (!is_file($this->key)) {
                throw new \InvalidArgumentException('Invalid key: Should be file path of private key', static::ERROR_KEY_INVALID);
            }

            $this->key = openssl_get_privatekey('file://' . $this->key, $this->passphrase ?? '');
        }

        if (!is_resource($this->key)) {
            throw new \InvalidArgumentException('Invalid key: Should be resource of private key', static::ERROR_KEY_INVALID);
        }
    }

    /**
     * URL safe base64 encode.
     *
     * First serialized the payload as json if it is an array.
     *
     * @param  array|string $data
     *
     * @return string
     *
     * @throws \InvalidArgumentException When JSON encode fails.
     */
    protected function urlSafeEncode($data) : string
    {
        if (is_array($data)) {
            $data = json_encode($data, JSON_UNESCAPED_SLASHES);
            $this->throwIfJsonError();
        }

        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * URL safe base64 decode.
     *
     * @param  array|string  $data
     * @param  bool          $asJson  Whether to parse as JSON (defaults to true).
     *
     * @return array|\stdClass|string
     *
     * @throws \InvalidArgumentException When JSON encode fails.
     */
    protected function urlSafeDecode(string $data, bool $asJson = true)
    {
        if (!$asJson) {
            return base64_decode(strtr($data, '-_', '+/'));
        }

        $data = json_decode(base64_decode(strtr($data, '-_', '+/')));
        $this->throwIfJsonError();

        return $data;
    }

    /**
     * Throw up if last json_encode/decode was a failure.
     *
     * @return void
     */
    protected function throwIfJsonError()
    {
        if (JSON_ERROR_NONE === json_last_error()) {
            return;
        }

        throw new \InvalidArgumentException('JSON failed: ' . json_last_error_msg(), static::ERROR_JSON_FAILED);
    }
}
