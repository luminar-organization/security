<?php

namespace Luminar\Security\Tests;

use Exception;
use Luminar\Core\Config\Config;
use Luminar\Core\Exceptions\ConfigException;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\EntityManager;
use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Luminar\Security\Authentication\LoginLink;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use Luminar\Security\Hashing\HMAC;
use PDOException;
use PHPUnit\Framework\TestCase;
use ReflectionException;

class LoginLinkTest extends TestCase
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
     * @throws ConfigException
     */
    public function testGenerateLink()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        defaultExpiration: 3600"
        );
        $hmac = new HMAC();
        $config = new Config(__DIR__ . '/fixtures');
        $session = new SessionManager();
        $loginLink = new LoginLink($config, $session, $this->connection);
        $link = $loginLink->generateLink("exampleIdentifier", null, "https://google.com/", "secret");
        $ourLink = "https://google.com/?identifier=exampleIdentifier&expires=" . time() + 3600 . "&hash=" . $hmac->hash("exampleIdentifier" . time()+3600, "secret");
        $this->assertEquals($ourLink, $link);
    }

    /**
     * @throws ConfigException
     */
    public function testExploitHash()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        defaultExpiration: 3600"
        );
        $hmac = new HMAC();
        $config = new Config(__DIR__ . '/fixtures');
        $session = new SessionManager();
        $loginLink = new LoginLink($config, $session, $this->connection);

        $expires = time() + 3600;
        $link = $loginLink->generateLink("exampleIdentifier", null, "https://google.com/", "secret");
        $hash = str_replace("https://google.com/?identifier=exampleIdentifier&expires=" . $expires . "&hash=", "", $link);

        $ourLink = "https://google.com/?identifier=root&expires=" . $expires. "&hash=" . $hash;

        $this->expectException(InvalidCredentials::class);
        $this->expectExceptionMessage("INVALID_SIGNATURE");
        $this->assertNotEquals($link, $ourLink);
        $loginLink->authenticate("root", $expires, $hash, "secret");
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws SuccessAuthentication
     * @throws SessionException
     * @throws \Luminar\Security\Exceptions\ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     */
    public function testSuccessLink()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        defaultExpiration: 3600"
        );
        $config = new Config(__DIR__ . '/fixtures');
        $session = new SessionManager();
        $loginLink = new LoginLink($config, $session, $this->connection);
        $identifier = "admin";
        $expires = time() + 3600;
        $link = $loginLink->generateLink($identifier, $expires, "https://google.com/", "secret");
        $hash = str_replace("https://google.com/?identifier=" . $identifier . "&expires=" . $expires . "&hash=", "", $link);
        $this->expectException(SuccessAuthentication::class);
        $loginLink->authenticate($identifier, $expires, $hash, "secret");
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws \Luminar\Security\Exceptions\ConfigException
     */
    public function testInvalidUser()
    {
        if(!$this->enable) return;
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    auth:\n        user: " . User::class . "\n        defaultExpiration: 3600"
        );
        $config = new Config(__DIR__ . '/fixtures');
        $session = new SessionManager();
        $loginLink = new LoginLink($config, $session, $this->connection);
        $identifier = "nimda";
        $expires = time() + 3600;
        $link = $loginLink->generateLink($identifier, $expires, "https://google.com/", "secret");
        $hash = str_replace("https://google.com/?identifier=" . $identifier . "&expires=" . $expires . "&hash=", "", $link);
        $this->expectException(InvalidCredentials::class);
        $this->expectExceptionMessage("INVALID_USER");
        $loginLink->authenticate($identifier, $expires, $hash, "secret");
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if(!$this->enable) return;

        @unlink(__DIR__ . '/fixtures/valid-config.yaml');
        $this->connection->query("DROP TABLE users");
    }
}