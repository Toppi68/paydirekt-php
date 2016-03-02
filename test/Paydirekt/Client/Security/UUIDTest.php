<?php

namespace Paydirekt\Client\Security;

class UUIDTest extends \PHPUnit_Framework_TestCase
{
    public function testThatUUIDIsGeneratedWithCorrectSize()
    {
        $uuid = UUID::createRandomUUID();

        $this->assertEquals(strlen($uuid), 36);
    }

    public function testThatDifferentUUIDsAreGenerated()
    {
        $uuid1 = UUID::createRandomUUID();
        $uuid2 = UUID::createRandomUUID();

        $this->assertTrue($uuid1 != $uuid2);
    }

    public function testThatValidUUIDsAreGenerated()
    {
        for ($i = 0; $i < 100; $i++) {
            $uuid = UUID::createRandomUUID();
            $result = UUID::isUUID($uuid);
            $this->assertTrue($result);
        }
    }

    public function testThatValidUUIDIsRecognized()
    {
        $validUUID = "4c15310a-7936-4a19-8d80-f2b7bd95dc9b";

        $result = UUID::isUUID($validUUID);

        $this->assertTrue($result);
    }

    public function testThatInvalidUUIDIsRecognized()
    {
        $invalidUUID = "4c15310a-7936-4a19-8d0-f2b7bd95dc9b";

        $result = UUID::isUUID($invalidUUID);

        $this->assertFalse($result);
    }
}
