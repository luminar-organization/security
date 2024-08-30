<?php

namespace Luminar\Security\Tests;

use Luminar\Database\ORM\Column;
use Luminar\Database\ORM\Entity;
use Luminar\Security\Authentication\AccessTokenInterface;

#[Entity(name: "tokens")]
class ExampleAccessToken implements AccessTokenInterface
{
    #[Column(name: "token")]
    protected string $token;

    #[Column(name: "expiration")]
    protected int $expiration;

    #[Column(name: "roles")]
    protected array $roles;

    public function getToken(): string
    {
        return $this->token;
    }

    public function setToken(string $token): void
    {
        $this->token = $token;
    }

    public function getExpiration(): int
    {
        return $this->expiration;
    }

    public function setExpiration(int $timestamp): void
    {
        $this->expiration = $timestamp;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function setRoles(array $roles): void
    {
        $this->roles = $roles;
    }
}