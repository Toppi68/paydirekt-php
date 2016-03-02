<?php

namespace Paydirekt\Client\Utility;

class Base64UrlTest extends \PHPUnit_Framework_TestCase
{
    public function testThatEncodingIsValidBase64Encoding()
    {
        $string = Base64Url::encode("GJlN718sQxN1unxbLWHVlcf0FgXw2kMyfRwD0mgTRME");
        $this->assertEquals($string, "R0psTjcxOHNReE4xdW54YkxXSFZsY2YwRmdYdzJrTXlmUndEMG1nVFJNRQ==");
    }

    public function testThatEncodingReplacesPlusSign()
    {
        $string = Base64Url::encode(hex2bin("80FBD2B5590DB7EE5A563C24BEB644E547E2C0AB9CB8DAE20C80AC5C6E2252F6784ED58E"));
        $this->assertEquals($string, "gPvStVkNt-5aVjwkvrZE5UfiwKucuNriDICsXG4iUvZ4TtWO");
    }

    public function testThatEncodingReplacesSlashSign()
    {
        $string = Base64Url::encode(hex2bin("5987FB2413DD5A4FFB77B2140A434AC966074C0AF7E3D198EB7BC56059650E5E06C1B0DB"));
        $this->assertEquals($string, "WYf7JBPdWk_7d7IUCkNKyWYHTAr349GY63vFYFllDl4GwbDb");
    }

    public function testThatDecodingIsValidBase64Decoding()
    {
        $string = Base64Url::decode("R0psTjcxOHNReE4xdW54YkxXSFZsY2YwRmdYdzJrTXlmUndEMG1nVFJNRQ==");
        $this->assertEquals($string, "GJlN718sQxN1unxbLWHVlcf0FgXw2kMyfRwD0mgTRME");
    }

    public function testThatDecodingReplacesMinusSign()
    {
        $string = Base64Url::decode("gPvStVkNt-5aVjwkvrZE5UfiwKucuNriDICsXG4iUvZ4TtWO");
        $this->assertEquals($string, hex2bin("80FBD2B5590DB7EE5A563C24BEB644E547E2C0AB9CB8DAE20C80AC5C6E2252F6784ED58E"));
    }

    public function testThatDecodingReplacesUnderscoreSign()
    {
        $string = Base64Url::decode("WYf7JBPdWk_7d7IUCkNKyWYHTAr349GY63vFYFllDl4GwbDb");
        $this->assertEquals($string, hex2bin("5987FB2413DD5A4FFB77B2140A434AC966074C0AF7E3D198EB7BC56059650E5E06C1B0DB"));
    }

    public function testThatValidBase64UrlEncodingsPassCheck()
    {
        $validBase64Encoding = "GJlN78sQxN1unxbLWHVlcf0FgXw2kMyfRwD0mgTRME=";

        $result = Base64Url::isBase64UrlEncoded($validBase64Encoding);

        $this->assertTrue($result);
    }

    public function testThatInvalidBase64UrlEncodingsFailCheck()
    {
        $invalidBase64Encoding = "GJlN78sQ/N1unxbLWHVlcf0FgXw2kMyfRwD0mgTRME=";

        $result = Base64Url::isBase64UrlEncoded($invalidBase64Encoding);

        $this->assertFalse($result);
    }

    public function testThatInvalidBase64UrlEncodingsWithOnlyPaddingFailCheck()
    {
        $invalidBase64Encoding = "=";

        while(strlen($invalidBase64Encoding) < 72)
        {
            $result = Base64Url::isBase64UrlEncoded($invalidBase64Encoding);
            $this->assertFalse($result);
            $invalidBase64Encoding .= "=";
        }
    }
}
