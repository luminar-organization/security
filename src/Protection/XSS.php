<?php

namespace Luminar\Security\Protection;

class XSS
{
    /**
     * @param string $text
     * @return string
     */
    public static function parse(string $text): string
    {
        return htmlentities($text, ENT_QUOTES, 'UTF-8');
    }
}