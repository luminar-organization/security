<?php

namespace Luminar\Security\Protection;

use Luminar\Http\Response;

class ClickJacking
{
    /**
     * @param Response $response
     * @return Response
     */
    public function handle(Response $response): Response
    {
        $response->setHeader("X-Frame-Options", "DENY");
        return $response;
    }
}