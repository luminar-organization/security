<?php

namespace Luminar\Security;

interface User
{
    /**
     * @return string
     */
    public function getIdentifier(): string;

    /**
     * @param string $identifier
     * @return void
     */
    public function setIdentifier(string $identifier): void;

    /**
     * @param string $password
     * @return void
     */
    public function setPassword(string $password): void;

    /**
     * @return string
     */
    public function getPassword(): string;

    /**
     * @return array
     */
    public function getRoles(): array;

    /**
     * @param array $roles
     * @return void
     */
    public function setRoles(array $roles): void;

    /**
     * @return string
     */
    public function getIdentifierColumn(): string;
}