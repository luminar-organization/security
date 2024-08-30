<?php

namespace Luminar\Security\Encryption;

class Base64
{
    /**
     * @param string $data
     * @return string
     */
    public function encrypt(string $data): string
    {
        return base64_encode($data);
    }

    /**
     * @param string $data
     * @return string
     */
    public function decrypt(string $data): string
    {
        return base64_decode($data);
    }
}