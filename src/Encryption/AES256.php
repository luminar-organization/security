<?php

namespace Luminar\Security\Encryption;

use Luminar\Security\Hashing\Sha256;

class AES256
{
    /**
     * @var Sha256 $sha256
     */
    protected Sha256 $sha256;


    public function __construct()
    {
        $this->sha256 = new Sha256();
    }

    /**
     * @param mixed $data
     * @param string $secretKey
     * @param string|null $secretVi
     * @return string
     */
    public function encrypt(mixed $data, string $secretKey, string $secretVi = null): string
    {
        $secretKey = $this->sha256->hash($secretKey);
        $secretVi = substr($this->sha256->hash($secretVi), 0, 16);
        return openssl_encrypt($data, 'AES-256-CBC', $secretKey, 0, $secretVi);
    }

    /**
     * @param mixed $data
     * @param string $secretKey
     * @param string|null $secretVi
     * @return string
     */
    public function decrypt(mixed $data, string $secretKey, string $secretVi = null): string
    {
        $secretKey = $this->sha256->hash($secretKey);
        $secretVi = substr($this->sha256->hash($secretVi), 0, 16);
        return openssl_decrypt($data, 'AES-256-CBC', $secretKey, 0, $secretVi);
    }
}