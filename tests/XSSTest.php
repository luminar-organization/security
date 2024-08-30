<?php

namespace Luminar\Security\Tests;

use Luminar\Security\Protection\XSS;
use PHPUnit\Framework\TestCase;

class XSSTest extends TestCase
{
    public function testXSS()
    {
        $text = "<h1>Hello World!</h1>";
        $parsedText = XSS::parse($text);
        $this->assertNotEquals($text, $parsedText);
    }
}