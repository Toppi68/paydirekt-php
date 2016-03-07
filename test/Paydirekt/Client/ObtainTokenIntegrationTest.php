<?php

namespace Paydirekt\Client;

use Paydirekt\Client\Security\Hmac;
use Paydirekt\Client\Security\Nonce;
use Paydirekt\Client\Security\UUID;

class ObtainTokenIntegrationTest extends \PHPUnit_Framework_TestCase
{
    const SANDBOX_ENDPOINT = "https://api.sandbox.paydirekt.de/api/merchantintegration/v1/token/obtain";
    const SANDBOX_API_KEY = "e81d298b-60dd-4f46-9ec9-1dbc72f5b5df";
    const SANDBOX_API_SECRET = "GJlN718sQxN1unxbLWHVlcf0FgXw2kMyfRwD0mgTRME=";

    public function testThatOAuth2TokenIsObtained()
    {
        $requestId = UUID::createRandomUUID();
        $randomNonce = Nonce::createRandomNonce();

        $now = new \DateTime("now", new \DateTimeZone('UTC'));
        $timestamp = $now->format('YmdHis');

         // Calculate the HMAC signature
        $signature = Hmac::signature($requestId, $timestamp, self::SANDBOX_API_KEY, self::SANDBOX_API_SECRET, $randomNonce);

        /*
         * For X-Date, use the RFC-1123 date format.
         * For X-Auth-Code, use the HMAC signature (not the API secret!)
         */
        $header = array();
        array_push($header, "X-Date: " .$now->format(DATE_RFC1123));
        array_push($header, "X-Request-ID: " .$requestId);
        array_push($header, "X-Auth-Key: " .self::SANDBOX_API_KEY);
        array_push($header, "X-Auth-Code: " .$signature);
        array_push($header, "Content-Type: application/hal+json;charset=utf-8");
        array_push($header, "Accept: application/hal+json");

        $payload = json_encode(array(
            'grantType' => 'api_key',
            'randomNonce' => $randomNonce
        ));

        $request = curl_init();
        curl_setopt($request, CURLOPT_URL, self::SANDBOX_ENDPOINT);
        curl_setopt($request, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($request, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($request, CURLOPT_CAINFO, __DIR__ ."/Thawte_Primary_Root_CA.pem");
        curl_setopt($request, CURLOPT_HTTPHEADER, $header);
        curl_setopt($request, CURLOPT_POST, 1);
        curl_setopt($request, CURLOPT_POSTFIELDS, $payload);

        $response = curl_exec($request);
        $responseCode = curl_getinfo($request, CURLINFO_HTTP_CODE);

        if ($responseCode != 200)
        {
            $message = ($responseCode > 0 ? "Unexpected status code " .$responseCode .": " .$response : "");
            $message .= (curl_error($request) ? curl_error($request) : "");
            throw new \RuntimeException($message);
        }

        curl_close($request);

        $responseDecoded = json_decode($response, true);
        $this->assertNotNull($responseDecoded['access_token']);
        $this->assertNotNull($responseDecoded['expires_in']);
        $this->assertGreaterThan(60, $responseDecoded['expires_in']);
    }
}
