<?php

namespace Luminar\Security\Hashing;

class Bcrypt
{
    /**
     * @param string $data
     * @param array $options
     * @return string
     */
    public function hash(string $data, array $options = ['cost' => 13]): string
    {
        return password_hash($data, PASSWORD_BCRYPT, $options);
    }

    /**
     * @param string $data
     * @param string $hash
     * @return bool
     */
    public function verify(string $data, string $hash): bool
    {
        return password_verify($data, $hash);
    }
}