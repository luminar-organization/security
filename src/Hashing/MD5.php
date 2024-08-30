<?php

namespace Luminar\Security\Hashing;

class MD5
{
    /**
     * @note This function should not be used to hash some important data because algorithm is very weak!!
     * @deprecated
     * @param string $data
     * @return string
     */
    public function hash(string $data): string
    {
        return md5($data);
    }
}