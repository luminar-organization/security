<?php

namespace Luminar\Security\Authentication;

use Exception;
use Luminar\Core\Config\Config;
use Luminar\Core\Support\Helpers;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\EntityManager;
use Luminar\Database\ORM\Repository;
use Luminar\Security\AccessControl;
use Luminar\Security\Exceptions\ConfigException;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use Luminar\Security\SecurityAttributes;
use Luminar\Security\Tests\User;
use Random\RandomException;
use ReflectionClass;
use ReflectionException;

class AccessToken
{
    /**
     * @var string $tokenObject
     */
    protected string $tokenObject;

    /**
     * @var Connection
     */
    protected Connection $connection;

    /**
     * @var Repository $repository
     */
    protected Repository $repository;

    /**
     * @var Config $config
     */
    protected Config $config;

    /**
     * @var EntityManager $entityManager
     */
    protected EntityManager $entityManager;

    /**
     * @param Config $config
     * @param Connection $connection
     * @throws ConfigException
     * @throws ReflectionException
     */
    public function __construct(Config $config, Connection $connection)
    {
        $this->connection = $connection;
        $this->config = $config;
        $this->entityManager = new EntityManager($connection);

        $token = $config->get("security.auth.token", false);
        if(!$token)
        {
            throw new ConfigException("Invalid configuration!");
        }

        $this->tokenObject = $token;
        $this->repository = new Repository($token, $connection);
    }

    /**
     * @param AccessTokenInterface $token
     * @param bool $useAccessList
     * @param string|null $path
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws SuccessAuthentication
     */
    public function authenticate(AccessTokenInterface $token, bool $useAccessList = false, string $path = null): void
    {
        /**
         * @var $tokenInstance AccessTokenInterface
         */
        $tokenInstance = $this->repository->findBy([
            SecurityAttributes::DATABASE_TOKEN => $token->getToken()
        ]);
        if(!$tokenInstance) {
            throw new InvalidCredentials("INVALID_TOKEN");
        }

        if(!($tokenInstance->getExpiration() >= time())) {
            throw new InvalidCredentials("EXPIRED_TOKEN");
        }
        if(!$useAccessList) {
            throw new SuccessAuthentication();
        }

        $accessControl = new AccessControl($this->config);
        if(!$accessControl->hasAccess($path, $tokenInstance->getRoles())) {
            throw new InvalidCredentials("ACCESS_DENIED_TOKEN");
        }

        throw new SuccessAuthentication();
    }

    /**
     * @param bool $useAccessList
     * @param ?string $role
     * @return AccessTokenInterface
     * @throws ConfigException
     * @throws RandomException
     * @throws Exception
     */
    public function generateAccessToken(bool $useAccessList = false, ?string $role = null): AccessTokenInterface
    {
        $token = new $this->tokenObject();
        if(!($token instanceof AccessTokenInterface))
        {
            throw new ConfigException("Invalid configuration!");
        }
        $token->setToken(Helpers::randomString($this->config->get("security.auth.access_token.length") ?? 32));
        if($useAccessList) {
            $token->setRoles([$role]);
        } else {
            $token->setRoles([]);
        }
        $token->setExpiration(time() + $this->config->get("security.auth.access_token.ttl") ?? 1800);



        $this->entityManager->persist($token);
        return $token;
    }
}