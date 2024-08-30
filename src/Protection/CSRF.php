<?php

namespace Luminar\Security\Protection;

use Luminar\Core\Support\Helpers;
use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Random\RandomException;

class CSRF
{
    /**
     * @param SessionManager $sessionManager
     * @return string
     * @throws SessionException
     * @throws RandomException
     */
    public function generateToken(SessionManager $sessionManager): string
    {
        $token = Helpers::randomString(25);
        $sessionManager->set('csrf_token', $token);
        return $token;
    }

    /**
     * @param string $token
     * @param SessionManager $sessionManager
     * @return bool
     * @throws SessionException
     */
    public function checkToken(string $token, SessionManager $sessionManager): bool
    {
        return $token and $token != '' and $token === $sessionManager->get('csrf_token', '');
    }
}