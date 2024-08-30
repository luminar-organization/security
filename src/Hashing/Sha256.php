<?php

namespace Luminar\Security\Hashing;

class Sha256
{
    /**
     * @param mixed $data
     * @return string
     */
    public function hash(mixed $data): string
    {
        return hash('sha256', $data);
    }
}