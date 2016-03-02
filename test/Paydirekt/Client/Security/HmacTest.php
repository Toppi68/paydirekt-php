<?php

namespace Paydirekt\Client\Security;

/*
 * Mock function returning a list of registered hashing algorithms, to allow for
 * tests concerning exceptions due to unsupported algorithms.
 */
function hash_algos() {
    global $mock_hash_algos;
    if ($mock_hash_algos) {
        return array("NoCrypoAlgorithmSupported");
    } else {
        return call_user_func_array('\hash_algos', func_get_args());
    }
}

class HmacTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        self::resetHashAlgosMock();
    }

    public function tearDown()
    {
        self::resetHashAlgosMock();
    }

	public function testThatStringToSignIsCorrectlyConcatenated()
	{
        $requestId = "f3fea5f3-60af-496f-ac3e-dbb10924e87a";
        $timestamp = "20160201094942";
        $apiKey = "e81d298b-60dd-4f46-9ec9-1dbc72f5b5df";
        $randomNonce = "Qg5f0Q3ly1Cwh5M9zcw57jwHI_HPoKbjdHLurXGpPg0yazdC6OWPpwnYi22bnB6S";

        $stringToSign = Hmac::stringToSign($requestId, $timestamp, $apiKey, $randomNonce);

        $this->assertEquals($stringToSign, "f3fea5f3-60af-496f-ac3e-dbb10924e87a:20160201094942:e81d298b-60dd-4f46-9ec9-1dbc72f5b5df:Qg5f0Q3ly1Cwh5M9zcw57jwHI_HPoKbjdHLurXGpPg0yazdC6OWPpwnYi22bnB6S");
    }

    public function testThatSignatureIsCorrectlyHashed()
    {
        $requestId = "f3fea5f3-60af-496f-ac3e-dbb10924e87a";
        $timestamp = "20160201094942";
        $apiKey = "e81d298b-60dd-4f46-9ec9-1dbc72f5b5df";
        $apiSecret = "JrXRHCnUegQJAYSJ5J6OvEuOUOpy2q2-MHPoH_IECRY=";
        $randomNonce = "Qg5f0Q3ly1Cwh5M9zcw57jwHI_HPoKbjdHLurXGpPg0yazdC6OWPpwnYi22bnB6S";

        $signature = Hmac::signature($requestId, $timestamp, $apiKey, $apiSecret, $randomNonce);

        $this->assertEquals($signature, "ps9MooGiTeTXIkPkUWbHG4rlF3wuTJuZ9qcMe-Y41xE=");
    }

    public function testThatRuntimeExceptionForUnknownCryptoAlgorithmsIsRaised()
    {
        global $mock_hash_algos;
        $mock_hash_algos = true;

        $requestId = "f3fea5f3-60af-496f-ac3e-dbb10924e87a";
        $timestamp = "20160201094942";
        $apiKey = "e81d298b-60dd-4f46-9ec9-1dbc72f5b5df";
        $apiSecret = "JrXRHCnUegQJAYSJ5J6OvEuOUOpy2q2-MHPoH_IECRY=";
        $randomNonce = "Qg5f0Q3ly1Cwh5M9zcw57jwHI_HPoKbjdHLurXGpPg0yazdC6OWPpwnYi22bnB6S";

        $this->setExpectedException("RuntimeException");
        Hmac::signature($requestId, $timestamp, $apiKey, $apiSecret, $randomNonce);
    }

    private function resetHashAlgosMock() {
        global $mock_hash_algos;
        $mock_hash_algos = false;
    }
}
