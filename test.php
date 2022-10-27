<?php

/*
 * This file is part of the PHP-JWT package.
 *
 * (c) Jitendra Adhikari <jiten.adhikary@gmail.com>
 *     <https://github.com/adhocore>
 *
 * Licensed under MIT license.
 */

use Ahc\Jwt\JWT;
use Ahc\Jwt\JWTException;

if (run_test()) {
    echo 'PHP version: ', PHP_VERSION, ", Tests passed\n";
}

function run_test()
{
    require __DIR__ . '/src/JWTException.php';
    require __DIR__ . '/src/ValidatesJWT.php';
    require __DIR__ . '/src/JWT.php';

    ini_set('assert.exception', 1);

    foreach (data1() as $d) {
        $d[] = [];

        list($key, $algo, $age, $leeway, $payload, $header) = $d;

        // HS
        $jwt   = new JWT($key, $algo, $age, $leeway);
        $token = $jwt->encode($payload, $header);
        assert(is_string($token));

        $decoded = $jwt->decode($token);
        assert(is_array($decoded));
        if (!isset($payload['exp'])) {
            unset($decoded['exp']);
        }
        assert($payload === $decoded);

        // RS
        $key   = __DIR__ . '/tests/stubs/priv.key';
        $jwt   = new JWT($key, str_replace('HS', 'RS', $algo), $age, $leeway);
        $token = $jwt->encode($payload, $header);
        assert(is_string($token));

        $decoded = $jwt->decode($token);
        assert(is_array($decoded));
        if (!isset($payload['exp'])) {
            unset($decoded['exp']);
        }
        assert($payload === $decoded);
    }

    foreach (data2() as $d) {
        list($key, $algo, $age, $leeway, $offset, $error, $token) = $d;

        $jwt   = new JWT($key, $algo, $age, $leeway);
        $token = is_string($token) ? $token : $jwt->encode($token);

        if ($offset) {
            $jwt->setTestTimestamp(time() + $offset);
        }

        try {
            $jwt->decode($token);
            assert(false);
        } catch (Exception $e) {
            assert($e->getCode() === $error);
            assert($e instanceof JWTException);
        }
    }

    foreach (data3() as $d) {
        list($method, $key, $arg) = $d;

        $jwt = new JWT($key, 'RS256');

        try {
            $jwt->{$method}($arg);
            assert(false);
        } catch (Exception $e) {
            assert($e instanceof JWTException);
        }
    }

    $jwt = (new JWT('dummy', 'HS256'))->registerKeys(['key1' => 'secret1', 'key2' => 'secret2']);

    $token = $jwt->encode($payload = ['a' => 1, 'exp' => time() + 1000], ['kid' => 'key2']);

    assert($payload === $jwt->decode($token));
    assert($payload === $jwt->decode($token, false));

    $jwt = new JWT('very^secre7');

    try {
        $jwt->encode([base64_decode('mF6u28o4K2cD3w==')]);
        assert(false);
    } catch (Exception $e) {
        assert($e instanceof JWTException);
    }

    return true;
}

function data1()
{
    return [
        ['secret', 'HS256', rand(10, 1000), rand(1, 10), [
            'uid'    => rand(),
            'scopes' => ['user'],
            'msg'    => 'fdsfdsf',
            'iss'    => 'https://mysite.com',
        ]],
        ['$ecRet-$ecRet', 'HS384', rand(101, 1000), rand(1, 10), [
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

function data2()
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

function data3()
{
    return [
        ['encode', 'not a file', ['uid' => rand()]],
        ['encode', __FILE__, ['uid' => rand()]],
        ['decode', 'not a file', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE0OTIwODkxODksImV4cCI6MTQ5MjA4OTE4OX0.fakesignature'],
        ['decode', __FILE__, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJuYmYiOjE0OTIwODkxODksImV4cCI6MTQ5MjA4OTE4OX0.fakesignature'],
    ];
}
