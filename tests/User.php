<?php

namespace Luminar\Security\Tests;

use Luminar\Database\ORM\Column;
use Luminar\Database\ORM\Entity;

#[Entity(name: "users")]
class User implements \Luminar\Security\User
{
    #[Column(name: "id")]
    private int $id;

    #[Column(name: "username")]
    private string $username;

    #[Column(name: "password")]
    private string $password;

    #[Column(name: "roles")]
    private array $roles;

    public function getId(): int
    {
        return $this->id;
    }

    public function setId(int $id): void
    {
        $this->id = $id;
    }

    public function getUsername(): string
    {
        return $this->username;
    }

    public function setUsername(string $username): void
    {
        $this->username = $username;
    }

    public function getPassword(): string
    {
        return $this->password;
    }

    public function setPassword(string $password): void
    {
        $this->password = $password;
    }

    public function getIdentifier(): string
    {
        return $this->getUsername();
    }

    public function setIdentifier(string $identifier): void
    {
        $this->setUsername($identifier);
    }

    public function setRoles(array $roles): void
    {
        $this->roles = $roles;
    }

    public function getRoles(): array
    {
        return $this->roles;
    }

    public function getIdentifierColumn(): string
    {
        return 'username';
    }
}