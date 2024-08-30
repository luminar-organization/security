<?php

namespace Luminar\Security\Tests;

use Luminar\Core\Config\Config;
use Luminar\Security\AccessControl;
use PHPUnit\Framework\TestCase;

class AccessControlTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        file_put_contents(__DIR__ . '/fixtures/valid-config.yaml',
            "security:\n    access_list:\n       - { name: /home, role: FULLY_AUTHENTICATED }\n       - { name: /admin, role: ROLE_ADMIN }"
        );
    }

    public function testHasAccess()
    {
        $config = new Config(__DIR__ . '/fixtures');
        $accessControl = new AccessControl($config);
        $this->assertTrue($accessControl->hasAccess("/home", ['FULLY_AUTHENTICATED']));
        $this->assertFalse($accessControl->hasAccess("/admin", ['FULLY_AUTHENTICATED']));
    }

    public function testGetPaths()
    {
        $config = new Config(__DIR__ . '/fixtures');
        $accessControl = new AccessControl($config);
        $this->assertEquals($accessControl->getPaths(), $config->get("security.access_list"));
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        @unlink(__DIR__ . '/fixtures/valid-config.yaml');
    }
}