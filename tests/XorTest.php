<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Encryption\XOREncryption;
use PHPUnit\Framework\TestCase;

class XorTest extends TestCase
{
    private XOREncryption $encryption;

    protected function setUp(): void
    {
        parent::setUp();
        $this->encryption = new XOREncryption();
    }

    public function testEncrypt()
    {
        $payload = "Hello, World!";
        $key = 'exampleKey';
        $encrypted = $this->encryption->encrypt($payload, $key);
        $this->assertNotEquals($payload, $encrypted);
    }

    public function testDecrypt()
    {
        $payload = "Hello, World!";
        $key = 'exampleKey';
        $encrypted = $this->encryption->encrypt($payload, $key);
        $decrypted = $this->encryption->decrypt($encrypted, $key);
        $this->assertEquals($payload, $decrypted);
    }

    public function testDecryptWrongKey()
    {
        $payload = "Hello, World!";
        $key = 'exampleKey';
        $wrongKey = 'exampleWrongKey';
        $encrypted = $this->encryption->encrypt($payload, $key);
        $decrypted = $this->encryption->decrypt($encrypted, $wrongKey);
        $this->assertNotEquals($payload, $decrypted);
    }
}