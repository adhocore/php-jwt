## adhocore/jwt [![build status](https://travis-ci.org/adhocore/jwt.svg?branch=master)](https://travis-ci.org/adhocore/jwt)

- Lightweight JSON Web Token (JWT) library for PHP7.

## Installation
```
composer require adhocore/jwt
```

## Usage
```php
use Ahc\Jwt\JWT;

// Instantiate with key, algo, maxAge and leeway.
$jwt = new JWT('secret', 'HS256', 3600, 10);

// Only the key is required. Defaults will be used for the rest:
// algo = HS256, maxAge = 3600, leeway = 0
$jwt = new JWT('secret');

// For RS* algo, the key should be either a resource like below:
$key = openssl_pkey_new(['digest_alg' => 'sha256', 'private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
// OR, a string with full path to the RSA private key like below:
$key = '/path/to/rsa.key';
// Then, instantiate JWT with this key and RS* as algo:
$jwt = new JWT($key, 'RS384');

// Generate JWT token from payload array.
$token = $jwt->generate([
    'uid'    => 1,
    'aud'    => 'http://site.com',
    'scopes' => ['user'],
    'iss'    => 'http://api.mysite.com',
]);

// Retrieve the payload array.
$payload = $jwt->parse($token);

// Oneliner.
$token   = (new JWT('topSecret', 'HS512', 1800))->generate(['uid' => 1, 'scopes' => ['user']]));
$payload = (new JWT('topSecret', 'HS512', 1800))->parse($token);

// Can pass extra headers into generate() with second parameter.
$token = $jwt->generate($payload, ['hdr' => 'hdr_value']);

// Spoof time() for testing token expiry.
$jwt->setTestTimestamp(time() + 10000);
// Throws Exception.
$jwt->parse($token);

// Call again without parameter to stop spoofing time().
$jwt->setTestTimestamp();

// Can use encode() instead of generate() and decode() instead of parse().
$token = $jwt->encode($payload);
$jwt->decode($token);

```

## Features

- Six algorithms supported:
```
'HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'
```
- Leeway support 0-120 seconds.
- Timestamp spoofing for tests.
- Passphrase support for `RS*` algos.
