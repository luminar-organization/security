<?php

namespace Luminar\Security\Tests;

use Luminar\Core\Config\Config;
use Luminar\Core\Exceptions\ConfigException;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\EntityManager;
use Luminar\Security\Authentication\AccessToken;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use PDOException;
use PHPUnit\Framework\TestCase;
use Random\RandomException;
use ReflectionException;

class AccessTokenTest extends TestCase
{
    /**
     * @var Connection $connection
     */
    protected Connection $connection;

    /**
     * @var bool $enable
     */
    protected bool $enable = false;

    /**
     * @var Config $config
     */
    protected Config $config;

    /**
     * @return void
     * @throws ConfigException
     * @throws ReflectionException
     * @throws \Luminar\Security\Exceptions\ConfigException
     */
    protected function setUp(): void
    {
        parent::setUp();
        try {
            $this->connection = new Connection("mysql:host=localhost;dbname=luminar-test", 'root');
            $entityManager = new EntityManager($this->connection);

            file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
                "security:\n    auth:\n        token: " . ExampleAccessToken::class
            );
            $this->config = new Config(__DIR__ . '/fixtures');

            $schema = $entityManager->schema(new ExampleAccessToken());
            $execute = $this->connection->query($schema['query']);
            if(!$execute) {
                return;
            }


            $this->enable = true;
        }  catch (PDOException $e) {
            // Repository does not support sqlite
            var_dump($e->getMessage());
            echo "\nWARNING! Repository does not support sqlite so you need to have for e.g. MySQL Server\n";
            return;
        }
    }

    /**
     * @return ExampleAccessToken|null
     * @throws \Luminar\Security\Exceptions\ConfigException
     * @throws RandomException
     * @throws ReflectionException
     */
    protected function generateToken(): ExampleAccessToken|null
    {
        if(!$this->enable) return null;
        $accessToken = new AccessToken($this->config, $this->connection);
        $token = $accessToken->generateAccessToken();

        return $token;
    }

    /**
     * @return void
     * @throws RandomException
     * @throws ReflectionException
     * @throws \Luminar\Security\Exceptions\ConfigException
     */
    public function testTokenGenerate()
    {
        $token = $this->generateToken();
        if(!$token) return;
        $this->assertNotNull($token->getToken());
        $this->assertTrue($token->getExpiration() >= time());
    }

    /**
     * @return void
     * @throws RandomException
     * @throws ReflectionException
     * @throws SuccessAuthentication
     * @throws \Luminar\Security\Exceptions\ConfigException
     * @throws InvalidCredentials
     */
    public function testTokenAuthSuccess()
    {
        $token = $this->generateToken();
        if(!$token) return;
        $this->assertNotNull($token->getToken());
        $this->assertTrue($token->getExpiration() >= time());
        $accessToken = new AccessToken($this->config, $this->connection);
        $this->expectException(SuccessAuthentication::class);
        $accessToken->authenticate($token);
    }

    /**
     * @return void
     * @throws ReflectionException
     * @throws SuccessAuthentication
     * @throws \Luminar\Security\Exceptions\ConfigException
     * @throws InvalidCredentials
     */
    public function testTokenAuthFailureCredentials()
    {
        $token = new ExampleAccessToken();
        $token->setToken("test");
        $token->setExpiration(time() + 3600);
        $token->setRoles([]);
        $accessToken = new AccessToken($this->config, $this->connection);
        $this->expectException(InvalidCredentials::class);
        $accessToken->authenticate($token);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
        if(!$this->enable) return;

        @unlink(__DIR__ . '/fixtures/valid-config.yaml');
        $this->connection->query("DROP TABLE tokens");
    }
}