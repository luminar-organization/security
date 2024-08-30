<?php

namespace Luminar\Security;

use Luminar\Core\Config\Config;
use Luminar\Security\Exceptions\ConfigException;

class AccessControl
{
    /**
     * @var array $paths
     */
    protected array $paths;

    /**
     * @param Config $config
     * @throws ConfigException
     */
    public function __construct(Config $config)
    {
        $paths = $config->get("security.access_list", false);
        if(!$paths) {
            throw new ConfigException("Invalid Access List!");
        }
        $this->paths = $paths;
    }

    /**
     * @param string $pathName
     * @return array|null
     */
    protected function getPath(string $pathName): ?array
    {
        foreach ($this->paths as $path) {
            if($path['name'] == $pathName) {
                return $path;
            }
        }
        return null;
    }

    /**
     * @param string $path
     * @param array $roles
     * @return bool
     */
    public function hasAccess(string $path, array $roles): bool
    {
        $path = $this->getPath($path);
        if (in_array($path['role'], $roles)) {
            return true;
        }
        return false;
    }

    /**
     * @return array
     */
    public function getPaths(): array
    {
        return $this->paths;
    }
}