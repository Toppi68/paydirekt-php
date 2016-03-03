# paydirekt PHP Client

PHP client implementation and samples for the [paydirekt REST API](https://www.paydirekt.de/haendler/merchant-api.html).

The source code demonstrates how to create valid requests for the paydirekt REST API using PHP.


## Requirements
* PHP 5.4 or later
* random_compat (for cryptographically secure pseudo-random bytes)


## Dev-Dependencies
* PHP cURL support (for integration tests)
* PHPUnit


## Usage
With Composer installed, clone this repository and install with:

```
composer install
```

Run the unit and integration tests with:

```
vendor/bin/phpunit
```

The integration tests run against the actual sandbox endpoint.


## HMAC Signature
The HMAC signature (to be used in the `X-Auth-Code` header) can be created using the [`Hmac.php`](src/Paydirekt/Client/Security/Hmac.php) class.

```
$randomNonce = Nonce::createRandomNonce();
$signature = Hmac::signature($requestId, $timestamp, $apiKey, $apiSecret, $randomNonce)
```

API-Key and API-Secret for the your shop are provided via the paydirekt merchant portal. Be aware that there are different credentials for sandbox and production.

Please refer to [`ObtainTokenIntegrationTest.php`](test/Paydirekt/Client/ObtainTokenIntegrationTest.php) for a full example how to build an http request with all header fields and payload.


## Security Advice
Do never print sensitive information to log files. The following values should never be logged:

* API-Secret
* OAuth2 Access Token


## License
MIT License.
