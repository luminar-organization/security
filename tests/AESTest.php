<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Encryption\AES256;
use PHPUnit\Framework\TestCase;

class AESTest extends TestCase
{
    /**
     * @var AES256 $AES256
     */
    protected AES256 $AES256;

    protected function setUp(): void
    {
        parent::setUp();
        $this->AES256 = new AES256();
    }

    /**
     * Test that the encryption and decryption work as expected.
     */
    public function testEncryptDecrypt()
    {
        $data = "Hello World!";
        $secretKey = 'my_secret_key';
        $secretVi = 'my_secret_vi';

        $encrypted = $this->AES256->encrypt($data, $secretKey, $secretVi);
        $this->assertNotEmpty($encrypted, "Encrypted data should not be empty");

        $decrypted = $this->AES256->decrypt($encrypted, $secretKey, $secretVi);
        $this->assertEquals($data, $decrypted, "Decrypted data should match the original data");
    }

    /**
     * Test that different data or keys produce different encrypted outputs
     */
    public function testDifferentInputs()
    {
        $data1 = "Hello, World!";
        $data2 = "Goodbye, World!";
        $secretKey1 = "my_secret_key_1";
        $secretKey2 = "my_secret_key_2";
        $secretVi = "my_secret_vi";

        $encrypted1 = $this->AES256->encrypt($data1, $secretKey1, $secretVi);
        $encrypted2 = $this->AES256->encrypt($data2, $secretKey2, $secretVi);

        $this->assertNotEquals($encrypted1, $encrypted2, "Encrypted data should not be different");

        $encrypted3 = $this->AES256->encrypt($data2, $secretKey1, $secretVi);

        $this->assertNotEquals($encrypted1, $encrypted3, "Encrypted data should not be different");
    }

    /**
     * Test decryption with an incorrect key.
     */
    public function testDecryptWithWrongKey()
    {
        $data = "Hello, World!";
        $secretKey = "my_secret_key";
        $wrongKey = "wrong_secret_key";
        $secretVi = "my_secret_vi";

        $encrypted = $this->AES256->encrypt($data, $secretKey, $secretVi);

        $decrypted = $this->AES256->decrypt($encrypted, $wrongKey, $secretVi);

        $this->assertNotEquals($data, $decrypted, "Decrypted data should not be different");
    }

    /**
     * Test encryption and decryption with a null IV.
     */
    public function testNullIv()
    {
        $data = "Hello, World!";
        $secretKey = "my_secret_key";

        $encrypted = $this->AES256->encrypt($data, $secretKey);

        $decrypted = $this->AES256->decrypt($encrypted, $secretKey);

        $this->assertEquals($data, $decrypted, "Decrypted data should match the original data");
    }
}