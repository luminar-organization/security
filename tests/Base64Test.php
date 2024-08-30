<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Encryption\Base64;
use PHPUnit\Framework\TestCase;

class Base64Test extends TestCase
{
    protected Base64 $base64;

    protected function setUp(): void
    {
        parent::setUp();
        $this->base64 = new Base64();
    }

    public function testEncrypt()
    {
        $payload = "Hello, World!";
        $encrypted = $this->base64->encrypt($payload);
        $this->assertNotEquals($payload,$encrypted);
    }

    public function testDecrypt()
    {
        $payload = "Hello, World!";
        $encrypted = $this->base64->encrypt($payload);
        $this->assertEquals($payload,$this->base64->decrypt($encrypted));
    }
}