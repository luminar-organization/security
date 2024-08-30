<?php

namespace Luminar\Security\Authentication;

use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Luminar\Security\SecurityAttributes;

class Utils
{
    /**
     * @var string $lastAuthenticationError
     */
    protected string $lastAuthenticationError;

    /**
     * @var string $lastUsername
     */
    protected string $lastUsername;

    /**
     * @param SessionManager $sessionManager
     * @throws SessionException
     */
    public function __construct(SessionManager $sessionManager)
    {
        $this->lastAuthenticationError = $sessionManager->get(SecurityAttributes::SESSION_ERROR, "");
        $this->lastUsername = $sessionManager->get(SecurityAttributes::SESSION_LAST_IDENTIFIER, "");
    }

    /**
     * @return string
     */
    public function getLastAuthenticationError(): string
    {
        return $this->lastAuthenticationError;
    }

    /**
     * @return string
     */
    public function getLastUsername(): string
    {
        return $this->lastUsername;
    }
}