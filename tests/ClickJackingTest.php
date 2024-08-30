<?php

namespace Luminar\Security\Tests;

use Luminar\Http\Response;
use Luminar\Security\Protection\ClickJacking;
use PHPUnit\Framework\TestCase;

class ClickJackingTest extends TestCase
{
    public function testHeader()
    {
        $clickJacking = new ClickJacking();
        $response = new Response("", 200);
        $parsedResponse = $clickJacking->handle($response);
        $this->assertNotNull($parsedResponse->getHeader("X-Frame-Options"));
    }
}