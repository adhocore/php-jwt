<?php

namespace Ahc\Jwt\Test;

use Ahc\Jwt\JWT;

/** @coversDefaultClass \Ahc\Jwt\JWT */
class JWTTest extends \PHPUnit\Framework\TestCase
{
    /** @dataProvider data1 */
    public function test_decode_encoded_token(string $key, string $algo, int $age, int $leeway, array $payload, array $header = [])
    {
        $jwt   = new JWT($key, $algo, $age, $leeway);
        $token = $jwt->encode($payload, $header);

        $this->assertTrue(is_string($token));
        $decoded = $jwt->decode($token);
        $this->assertTrue(is_array($decoded));

        // Normalize.
        if (!isset($payload['exp'])) {
            unset($decoded['exp']);
        }

        $this->assertSame($payload, $decoded);
    }

    public function test_json_fail()
    {
        $this->expectException(\InvalidArgumentException::class);

        $jwt = new JWT('very^secre7');

        try {
            $jwt->encode([random_bytes(10)]);
        } catch (\Exception $e) {
            $this->assertSame($e->getCode(), JWT::ERROR_JSON_FAILED, $e->getMessage());

            throw $e;
        }
    }

    /** @dataProvider data2 */
    public function test_decode_fail(string $key, string $algo, int $age, int $leeway, int $offset, int $error, $token)
    {
        $this->expectException(\InvalidArgumentException::class);

        $jwt   = new JWT($key, $algo, $age, $leeway);
        $token = is_string($token) ? $token : $jwt->encode($token);

        if ($offset) {
            $jwt->setTestTimestamp(time() + $offset);
        }

        try {
            $jwt->decode($token);
        } catch (\Exception $e) {
            $this->assertSame($e->getCode(), $error, $e->getMessage());

            throw $e;
        }
    }

    /** @dataProvider data1 */
    public function test_rs_decode_encoded(string $key, string $algo, int $age, int $leeway, array $payload, array $header = [])
    {
        $key   = __DIR__ . '/stubs/priv.key';
        $jwt   = new JWT($key, str_replace('HS', 'RS', $algo), $age, $leeway);
        $token = $jwt->encode($payload, $header);

        $this->assertTrue(is_string($token));
        $decoded = $jwt->decode($token);
        $this->assertTrue(is_array($decoded));

        // Normalize.
        if (!isset($payload['exp'])) {
            unset($decoded['exp']);
        }

        $this->assertSame($payload, $decoded);
    }

    /** @dataProvider data3 */
    public function test_rs_invalid_key(string $method, string $key, $arg)
    {
        $this->expectException(\InvalidArgumentException::class);

        $jwt = new JWT($key, 'RS256');

        try {
            $jwt->{$method}($arg);
        } catch (\Exception $e) {
            $this->assertSame($e->getCode(), JWT::ERROR_KEY_INVALID, $e->getMessage());

            throw $e;
        }
    }

    public function data1() : array
    {
        return [
            ['secret', 'HS256', rand(10, 1000), rand(1, 10), [
                'uid'    => rand(),
                'scopes' => ['user'],
                'msg'    => 'fdsfdsf',
                'iss'    => 'https://mysite.com',
            ]],
            ['$ecRet-$ecRet', 'HS384', rand(10, 1000), rand(1, 10), [
                'uid'    => rand(),
                'scopes' => ['admin'],
                'exp'    => time() + 100,
                'iss'    => 'https://my.site.com',
            ]],
            ['s3cr3t.s3cr3t', 'HS512', rand(10, 1000), rand(1, 10), [
                'uid' => rand(),
                'iat' => time() - 10,
                'aud' => 'https://site.com',
            ]],
            ['secret|$ecRet', 'HS256', rand(10, 1000), rand(1, 10), [
            ]],
            ['|s3cr3t|secret', 'HS384', rand(10, 1000), rand(1, 10), [
                'sub' => 'xyz',
            ]],
            ['secret', 'HS512', rand(10, 1000), rand(1, 10), [
                '_' . rand() => rand(),
            ]],
        ];
    }

    public function data2() : array
    {
        return [
            ['topsecret',     'HS256', 5,  0,  0,  JWT::ERROR_TOKEN_INVALID,    'a.b'],
            ['$ecRet-$ecRet', 'HS384', 5,  0,  0,  JWT::ERROR_ALGO_MISSING,     'W10.b.c'],
            ['$$ecRet^&*',    'HS512', 5,  0,  0,  JWT::ERROR_ALGO_UNSUPPORTED, 'eyJhbGciOiJXVEYifQ.b.c'],
            ['$$ecRet^&*',    'HS512', 5,  0,  0,  JWT::ERROR_SIGNATURE_FAILED, implode('.', [
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9',
                'eyJuYmYiOjE0OTIwODkxODksImV4cCI6MTQ5MjA4OTE4OX0',
                'fakesignature',
            ])],

            ['njb(vgcf+dcv', 'HS512',  10,  0,  0,  JWT::ERROR_TOKEN_EXPIRED, [
                'iat' => time() - 11,
            ]],
            ['hedncpoyt978t', 'HS256',  50,  1,  50,  JWT::ERROR_TOKEN_EXPIRED, [
                'iat' => time(),
            ]],
            ['hkjhkjkh3c3t', 'HS384',  40,  0,  100,  JWT::ERROR_TOKEN_EXPIRED, [
                'iat' => time() + 50,
            ]],
            ['s3cr3t.s3cr3t', 'HS256',  60,  0,  20,  JWT::ERROR_TOKEN_EXPIRED, [
                'iat' => time() - 50,
            ]],
            ['s3cr3t-2l096', 'HS256',  4,  0,  5,  JWT::ERROR_TOKEN_EXPIRED, [
                'iat' => time(),
            ]],
            ['6zmo0.s3cr3t', 'HS256',  50,  0,  25,  JWT::ERROR_TOKEN_EXPIRED, [
                'exp' => time() + 20,
            ]],
            [',.j!f,-o==?', 'HS512',  1,  0,  15,  JWT::ERROR_TOKEN_EXPIRED, [
                'exp' => time() + 10,
            ]],
            ['s3cr3t.s33t', 'HS384',  10,  2,  0,  JWT::ERROR_TOKEN_EXPIRED, [
                'exp' => time() - 10,
            ]],
            ['hjn{jnml9kj', 'HS256',  10,  0,  11,  JWT::ERROR_TOKEN_EXPIRED, [
                '_' => rand(),
            ]],
            ['*&qvk_=KNBJ', 'HS512',  10,  0,  -1,  JWT::ERROR_TOKEN_NOT_NOW, [
                'nbf' => time(),
            ]],
            ['NN=KK(*({:BJ', 'HS512',  10,  0,  -20,  JWT::ERROR_TOKEN_NOT_NOW, [
                'nbf' => time() - 10,
            ]],
        ];
    }

    public function data3()
    {
        return [
            ['encode', 'not a file', ['uid' => rand()]],
            ['encode', __FILE__, ['uid' => rand()]],
            ['decode', 'not a file', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE0OTIwODkxODksImV4cCI6MTQ5MjA4OTE4OX0.fakesignature'],
            ['decode', __FILE__, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE0OTIwODkxODksImV4cCI6MTQ5MjA4OTE4OX0.fakesignature'],
        ];
    }
}
