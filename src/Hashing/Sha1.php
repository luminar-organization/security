<?php

namespace Luminar\Security\Hashing;

class Sha1
{
    /**
     * @param string $data
     * @param bool $binary
     * @return string
     */
    public function hash(string $data, bool $binary = false): string
    {
        return sha1($data, $binary);
    }
}