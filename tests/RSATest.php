<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Encryption\RSA;
use PHPUnit\Framework\TestCase;

class RSATest extends TestCase
{
    /**
     * @var RSA
     */
    protected RSA $rsa;

    /**
     * @var string
     */
    protected string $publicKey;

    /**
     * @var string
     */
    protected string $privateKey;

    /**
     * Set up the test environment.
     */
    protected function setUp(): void
    {
        $this->rsa = new RSA();

        $keyResource = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($keyResource, $privateKey);
        $this->privateKey = $privateKey;

        $keyDetails = openssl_pkey_get_details($keyResource);
        $this->publicKey = $keyDetails['key'];
    }

    /**
     * Test RSA encryption and decryption.
     */
    public function testEncryptionDecryption()
    {
        $data = "Hello, RSA!";

        $encrypted = $this->rsa->encrypt($data, $this->publicKey);

        $decrypted = $this->rsa->decrypt($encrypted, $this->privateKey);

        $this->assertEquals($data, $decrypted);
    }

    /**
     * Test encryption and decryption with different keys (should fail).
     */
    public function testEncryptionWithDifferentKeys()
    {
        $data = "This should fail";

        $encrypted = $this->rsa->encrypt($data, $this->publicKey);

        $anotherKeyResource = openssl_pkey_new([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($anotherKeyResource, $anotherPrivateKey);

        $decrypted = $this->rsa->decrypt($encrypted, $anotherPrivateKey);

        $this->assertNotEquals($data, $decrypted);
    }
}