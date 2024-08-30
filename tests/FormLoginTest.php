<?php

namespace Luminar\Security\Tests;

use Exception;
use Luminar\Core\Config\Config;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\EntityManager;
use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Luminar\Http\Request;
use Luminar\Security\Authentication\FormLogin;
use Luminar\Security\Exceptions\ConfigException;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use Luminar\Security\Exceptions\TokenException;
use PDOException;
use PHPUnit\Framework\TestCase;
use ReflectionException;

class FormLoginTest extends TestCase
{
    /**
     * @var Connection $connection
     */
    protected Connection $connection;

    /**
     * @var EntityManager $entityManager
     */
    protected EntityManager $entityManager;

    /**
     * @var bool $enable
     */
    protected bool $enable;

    /**
     * @return void
     * @throws Exception
     */
    protected function setUp(): void
    {
        parent::setUp();
        $this->enable = false;
        try {
            $this->connection = new Connection("mysql:host=localhost;dbname=luminar-test", 'root');
            $this->entityManager = new EntityManager($this->connection);

            $schema = $this->entityManager->schema(new User());
            $execute = $this->connection->query($schema['query']);
            if(!$execute) {
                return;
            }
            $user = new User();
            $user->setUsername('admin');
            $user->setRoles(['ROLE_USER']);
            $user->setPassword('$2a$13$ZAgND3ypYo87fGaFEnQH..00EWoE2zQie9HUavI3I56yj6RYCZyWO'); // Hash of password: admin
            $this->entityManager->persist($user);
            $this->enable = true;
        }  catch (PDOException $e) {
            // Repository does not support sqlite
            echo "\nWARNING! Repository does not support sqlite so you need to have for e.g. MySQL Server\n";
            $this->assertTrue(true);
            return;
        }
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws TokenException
     * @throws \Luminar\Core\Exceptions\ConfigException
     * @throws SessionException
     * @throws InvalidCredentials
     * @throws SuccessAuthentication
     * @throws ReflectionException
     */
    public function testLoginInvalidConfig()
    {
        if(!$this->enable) return;
        $config = new Config(__DIR__ . '/fixtures');
        $request = new Request();
        $this->expectException(ConfigException::class);
        new FormLogin($request, $config, new SessionManager(), $this->connection);
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws TokenException
     * @throws \Luminar\Core\Exceptions\ConfigException
     */
    public function testLoginTokenException()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        userIdentifier: username\n        userPassword: password\n        csrf: true"
        );
        $config = new Config(__DIR__ . '/fixtures');
        $request = new Request([], [
            '__username' => 'admin',
            '__password' => 'nimda',
            '__token' => 'invalid_token'
        ]);
        $session = new SessionManager();
        $this->expectException(TokenException::class);
        new FormLogin($request, $config, $session, $this->connection);
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws TokenException
     * @throws \Luminar\Core\Exceptions\ConfigException
     */
    public function testLoginInvalidCredentials()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        userIdentifier: username\n        userPassword: password\n        csrf: false"
        );
        $config = new Config(__DIR__ . '/fixtures');
        $request = new Request([], [
            '__username' => 'admin',
            '__password' => 'nimda',
            '__token' => ''
        ]);
        $session = new SessionManager();
        $this->expectException(InvalidCredentials::class);
        new FormLogin($request, $config, $session, $this->connection);
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws TokenException
     * @throws \Luminar\Core\Exceptions\ConfigException
     */
    public function testLoginSuccess()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        csrf: false"
        );
        $config = new Config(__DIR__ . '/fixtures');
        $request = new Request([], [
            '__username' => 'admin',
            '__password' => 'admin',
            '__token' => ''
        ]);
        $session = new SessionManager();
        $this->expectException(SuccessAuthentication::class);
        new FormLogin($request, $config, $session, $this->connection);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if(!$this->enable) return;

        @unlink(__DIR__ . '/fixtures/valid-config.yaml');
        $this->connection->query("DROP TABLE users");
    }
}