## adhocore/jwt

If you are new to JWT or want to refresh your familiarity with it, please check [jwt.io](https://jwt.io/)

[![Latest Version](https://img.shields.io/github/release/adhocore/php-jwt.svg?style=flat-square)](https://github.com/adhocore/php-jwt/releases)
[![Travis Build](https://img.shields.io/travis/adhocore/php-jwt/master.svg?style=flat-square)](https://travis-ci.org/adhocore/php-jwt?branch=master)
[![Scrutinizer CI](https://img.shields.io/scrutinizer/g/adhocore/php-jwt.svg?style=flat-square)](https://scrutinizer-ci.com/g/adhocore/php-jwt/?branch=master)
[![Codecov branch](https://img.shields.io/codecov/c/github/adhocore/php-jwt/master.svg?style=flat-square)](https://codecov.io/gh/adhocore/php-jwt)
[![StyleCI](https://styleci.io/repos/88168137/shield)](https://styleci.io/repos/88168137)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE)


- Lightweight JSON Web Token (JWT) library for PHP7.
- If you still use PHP5.6, use version [0.1.2](https://github.com/adhocore/php-jwt/releases/tag/0.1.2)

## Installation
```sh
# PHP7.0+
composer require adhocore/jwt

# PHP5.6
composer require adhocore/jwt:0.1.2

# For PHP5.4-5.5, use version 0.1.2 with a polyfill for https://php.net/hash_equals
```

## Features

- Six algorithms supported:
```
'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
```
- `kid` support.
- Leeway support 0-120 seconds.
- Timestamp spoofing for tests.
- Passphrase support for `RS*` algos.

## Usage

```php
use Ahc\Jwt\JWT;

// Instantiate with key, algo, maxAge and leeway.
$jwt = new JWT('secret', 'HS256', 3600, 10);
```

> Only the key is required. Defaults will be used for the rest:
```php
$jwt = new JWT('secret');
// algo = HS256, maxAge = 3600, leeway = 0
```

> For `RS*` algo, the key should be either a resource like below:
```php
$key = openssl_pkey_new([
    'digest_alg' => 'sha256',
    'private_key_bits' => 1024,
    'private_key_type' => OPENSSL_KEYTYPE_RSA,
]);
```

> OR, a string with full path to the RSA private key like below:
```php
$key = '/path/to/rsa.key';

// Then, instantiate JWT with this key and RS* as algo:
$jwt = new JWT($key, 'RS384');
```

***Pro***
You dont need to specify pub key path, that is deduced from priv key.

> Generate JWT token from payload array:
```php
$token = $jwt->encode([
    'uid'    => 1,
    'aud'    => 'http://site.com',
    'scopes' => ['user'],
    'iss'    => 'http://api.mysite.com',
]);
```

> Retrieve the payload array:
```php
$payload = $jwt->decode($token);
```

> Oneliner:
```php
$token   = (new JWT('topSecret', 'HS512', 1800))->encode(['uid' => 1, 'scopes' => ['user']]));
$payload = (new JWT('topSecret', 'HS512', 1800))->decode($token);
```

***Pro***

> Can pass extra headers into encode() with second parameter:
```php
$token = $jwt->encode($payload, ['hdr' => 'hdr_value']);
```

#### Test mocking

> Spoof time() for testing token expiry:
```php
$jwt->setTestTimestamp(time() + 10000);

// Throws Exception.
$jwt->parse($token);
```

> Call again without parameter to stop spoofing time():
```php
$jwt->setTestTimestamp();
```

#### Examples with `kid`

```php
$jwt = new JWT(['key1' => 'secret1', 'key2' => 'secret2']);

// Use key2
$token = $jwt->encode(['a' => 1, 'exp' => time() + 1000], ['kid' => 'key2']);

$payload = $jwt->decode($token);

$token = $jwt->encode(['a' => 1, 'exp' => time() + 1000], ['kid' => 'key3']);
// -> Exception with message Unknown key ID key3
```

## Stabillity

The library is now marked at version `1.*.*` as being stable in functionality and API.

### Integration

#### Phalcon

Check [adhocore/phalcon-ext](https://github.com/adhocore/phalcon-ext).

#### Laravel/Lumen

Coming soon [laravel-jwt](https://github.com/adhocore/laravel-jwt).

### Consideration

Be aware of some security related considerations as outlined [here](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/) which can be valid for any JWT implementations.
