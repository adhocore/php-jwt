## adhcore/jwt [![build status](https://travis-ci.org/adhocore/jwt.svg?branch=master)](https://travis-ci.org/adhocore/jwt)

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
