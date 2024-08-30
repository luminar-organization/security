<?php

namespace Luminar\Security\Hashing;

class Argon2i
{
    /**
     * @param string $data
     * @param array $options
     * @return string
     */
    public function hash(string $data, array $options = []): string
    {
        return password_hash($data, PASSWORD_ARGON2I, $options);
    }

    /**
     * @param string $data
     * @param string $hashedData
     * @return bool
     */
    public function verify(string $data, string $hashedData): bool
    {
        return password_verify($data, $hashedData);
    }
}