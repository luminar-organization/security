<?php

namespace Luminar\Security\Encryption;

class XOREncryption
{
    /**
     * @param string $data
     * @param string $key
     * @return string
     */
    public function encrypt(string $data, string $key): string
    {
        $key = str_split($key);
        $data = str_split($data);
        foreach ($data as $i => $char) {
            $data[$i] = chr(ord($char) ^ ord($key[$i % count($key)]));
        }
        return implode('', $data);
    }

    /**
     * @param string $data
     * @param string $key
     * @return string
     */
    public function decrypt(string $data, string $key): string
    {
        // XOR Encryption is symmetric
        return $this->encrypt($data, $key);
    }
}