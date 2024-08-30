<?php

namespace Luminar\Security\Authentication;

interface AccessTokenInterface
{
    public function getToken(): string;
    public function setToken(string $token): void;
    public function getExpiration(): int;
    public function setExpiration(int $timestamp): void;
    public function getRoles(): array;
    public function setRoles(array $roles): void;
}