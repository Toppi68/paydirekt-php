<?php

namespace Paydirekt\Client\Security;

class NonceTest extends \PHPUnit_Framework_TestCase
{
    public function testThatNonceIsGeneratedWithCorrectSize()
    {
        $nonce = Nonce::createRandomNonce();

        $this->assertEquals(strlen($nonce), 64);
    }

    public function testThatDifferentNoncesAreGenerated()
    {
        $nonce1 = Nonce::createRandomNonce();
        $nonce2 = Nonce::createRandomNonce();

        $this->assertTrue($nonce1 != $nonce2);
    }
}
