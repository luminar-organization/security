<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Hashing\Argon2i;
use Luminar\Security\Hashing\Argon2id;
use Luminar\Security\Hashing\Bcrypt;
use Luminar\Security\Hashing\HMAC;
use Luminar\Security\Hashing\MD5;
use Luminar\Security\Hashing\Sha1;
use Luminar\Security\Hashing\Sha256;
use PHPUnit\Framework\TestCase;

class HashingTest extends TestCase
{
    public function testArgon2i()
    {
        $Argon2i = new Argon2i();
        $payload = "Example Payload";
        $encrypted = $Argon2i->hash($payload);
        $this->assertTrue($Argon2i->verify($payload, $encrypted));
    }

    public function testArgon2id()
    {
        $Argon2id = new Argon2id();
        $payload = "Example Payload";
        $encrypted = $Argon2id->hash($payload);
        $this->assertTrue($Argon2id->verify($payload, $encrypted));
    }

    public function testBcrypt()
    {
        $Bcrypt = new Bcrypt();
        $payload = "Example Payload";
        $encrypted = $Bcrypt->hash($payload);
        $this->assertTrue($Bcrypt->verify($payload, $encrypted));
    }

    public function testHmac()
    {
        $Hmac = new HMAC();
        $payload = "Example Payload";
        $secret = "Secret Key!";
        $encrypted1 = $Hmac->hash($payload, $secret);
        $encrypted2 = $Hmac->hash($payload, $secret);
        $this->assertEquals($encrypted1, $encrypted2);
    }

    public function testMd5()
    {
        $Md5 = new MD5();
        $payload = "Example Payload";
        $encrypted = $Md5->hash($payload);
        $this->assertnotEquals($encrypted, $payload);
    }

    public function testSha1()
    {
        $Sha1 = new Sha1();
        $payload = "Example Payload";
        $encrypted = $Sha1->hash($payload);
        $this->assertnotEquals($encrypted, $payload);
    }

    public function testSha256()
    {
        $Sha256 = new Sha256();
        $payload = "Example Payload";
        $encrypted = $Sha256->hash($payload);
        $this->assertnotEquals($encrypted, $payload);
    }
}