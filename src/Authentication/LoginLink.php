<?php

namespace Luminar\Security\Authentication;

use Luminar\Core\Config\Config;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\Repository;
use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Luminar\Security\Exceptions\ConfigException;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use Luminar\Security\Hashing\HMAC;
use Luminar\Security\SecurityAttributes;
use Luminar\Security\User;
use ReflectionException;

class LoginLink
{
    /**
     * @var Connection $connection
     */
    protected Connection $connection;

    /**
     * @var SessionManager $sessionManager
     */
    protected SessionManager $sessionManager;

    /**
     * @var HMAC $HMAC
     */
    protected HMAC $HMAC;

    /**
     * @var Config $config
     */
    protected Config $config;

    /**
     * @var string|array|mixed|null $userObject
     */
    protected string $userObject;

    /**
     * @var int $defaultExpiration
     */
    protected int $defaultExpiration;

    /**
     * @param Config $config
     * @param SessionManager $sessionManager
     * @param Connection $connection
     */
    public function __construct(Config $config, SessionManager $sessionManager, Connection $connection)
    {
        $this->sessionManager = $sessionManager;
        $this->connection = $connection;
        $this->config = $config;
        $this->HMAC = new HMAC();

        $this->userObject = $config->get("security.auth.user", "");
        $this->defaultExpiration = $config->get("security.auth.defaultExpiration", "");

    }

    /**
     * @param string $userIdentifier
     * @param int $expires
     * @param string $hash
     * @param string $secret
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SuccessAuthentication
     * @throws SessionException
     */
    public function authenticate(string $userIdentifier, int $expires, string $hash, string $secret): void
    {
        $serverHash = $this->HMAC->hash($userIdentifier . $expires, $secret);
        if(!hash_equals($hash, $serverHash)) {
            throw new InvalidCredentials("INVALID_SIGNATURE");
        }
        if($expires < microtime()) {
            throw new InvalidCredentials("LINK_EXPIRED");
        }
        $userRepo = new Repository($this->userObject, $this->connection);
        $exampleUser = new $this->userObject;
        if(!($exampleUser instanceof User)) {
            throw new ConfigException("INVALID_USER_CLASS");
        }
        $user = $userRepo->findBy([
            $exampleUser->getIdentifierColumn() => $userIdentifier
        ]);
        if(!$user) {
            throw new InvalidCredentials("INVALID_USER");
        }

        if(!($user instanceof User)) {
            throw new ConfigException("INVALID_USER_CLASS");
        }

        $this->sessionManager->set(SecurityAttributes::SESSION_LOGGED_BOOL, true);
        $this->sessionManager->set(SecurityAttributes::SESSION_IDENTIFIER, $user->getIdentifier());
        $this->sessionManager->set(SecurityAttributes::SESSION_ROLES, $user->getRoles());

        throw new SuccessAuthentication();
    }

    /**
     * @param string $userIdentifier
     * @param int|null $expires
     * @param string $authenticateEndpoint
     * @param string $secret
     * @return string
     */
    public function generateLink(string $userIdentifier, ?int $expires, string $authenticateEndpoint, string $secret): string
    {
        if(!$expires) {
            $expires = $this->defaultExpiration + time();
        }
        $authenticateEndpoint .= "?identifier=" . $userIdentifier . "&expires=" . $expires . "&hash=" . $this->HMAC->hash($userIdentifier . $expires, $secret);
        return $authenticateEndpoint;
    }
}