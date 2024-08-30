<?php

namespace Luminar\Security\Authentication;

use Luminar\Core\Config\Config;
use Luminar\Database\Connection\Connection;
use Luminar\Database\ORM\Repository;
use Luminar\Http\Exceptions\SessionException;
use Luminar\Http\Managers\SessionManager;
use Luminar\Http\Request;
use Luminar\Security\Protection\CSRF;
use Luminar\Security\Exceptions\ConfigException;
use Luminar\Security\Exceptions\InvalidCredentials;
use Luminar\Security\Exceptions\SuccessAuthentication;
use Luminar\Security\Exceptions\TokenException;
use Luminar\Security\Hashing\Bcrypt;
use Luminar\Security\SecurityAttributes;
use Luminar\Security\User;
use ReflectionException;

class FormLogin
{
    /**
     * @var Bcrypt $crypt
     */
    protected Bcrypt $bcrypt;

    /**
     * @var Config $config
     */
    protected Config $config;

    /**
     * @var Request $request
     */
    protected Request $request;

    /**
     * @var SessionManager $session
     */
    protected SessionManager $session;

    /**
     * @var Connection $connection
     */
    protected Connection $connection;

    /**
     * @var string|array|mixed|null $userObject
     */
    protected string $userObject;

    /**
     * @var bool|array|mixed|null $useCsrf
     */
    protected bool $useCsrf;

    /**
     * @param Request $request
     * @param Config $config
     * @param SessionManager $sessionManager
     * @param Connection $connection
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws TokenException
     */
    public function __construct(Request $request, Config $config, SessionManager $sessionManager, Connection $connection)
    {
        $this->request = $request;
        $this->session = $sessionManager;
        $this->connection = $connection;
        $this->config = $config;
        $this->bcrypt = new Bcrypt();

        $this->userObject = $config->get("security.auth.user", "");
        $this->useCsrf = $config->get('security.auth.csrf', false);
        if(!$this->userObject) {
            throw new ConfigException("INVALID_CONFIGURATION");
        }

        $this->authenticate();
    }

    /**
     * @return void
     * @throws ConfigException
     * @throws InvalidCredentials
     * @throws ReflectionException
     * @throws SessionException
     * @throws SuccessAuthentication
     * @throws TokenException
     */
    private function authenticate(): void
    {
        $csrf = new CSRF();
        $credentials = $this->getCredentials();

        $this->session->set(SecurityAttributes::SESSION_LAST_IDENTIFIER, $credentials["identifier"]);

        if($this->useCsrf) {
            if(!$csrf->checkToken($credentials['csrf_token'], $this->session)) {
                $this->session->set(SecurityAttributes::SESSION_ERROR, 'invalid_token');
                throw new TokenException("INVALID_TOKEN");
            }
        }

        $repository = new Repository($this->userObject, $this->connection);
        $exampleUser = new $this->userObject();
        if(!$exampleUser or !($exampleUser instanceof User)) {
            $this->session->set(SecurityAttributes::SESSION_ERROR, 'internal_server_error');
            throw new ConfigException("INVALID_USER_CLASS");
        }

        $user = $repository->findBy([
            $exampleUser->getIdentifierColumn() => $credentials['identifier']
        ]);
        if(!$user) {
            $this->session->set(SecurityAttributes::SESSION_ERROR, 'user_not_found');
            throw new InvalidCredentials($credentials['identifier'] . "_USER_NOT_FOUND");
        }
        if(!($user instanceof User)) {
            $this->session->set(SecurityAttributes::SESSION_ERROR, 'internal_server_error');
            throw new ConfigException("INVALID_USER_CLASS");
        }
        $userPassword = $user->getPassword();
        if(!$this->bcrypt->verify($credentials['password'], $userPassword)) {
            $this->session->set(SecurityAttributes::SESSION_ERROR, 'invalid_credentials');
            throw new InvalidCredentials("INVALID_PASSWORD");
        }

        $this->session->set(SecurityAttributes::SESSION_LOGGED_BOOL, true);
        $this->session->set(SecurityAttributes::SESSION_IDENTIFIER, $user->getIdentifier());
        $this->session->set(SecurityAttributes::SESSION_ROLES, $user->getRoles());

        throw new SuccessAuthentication();
    }

    private function getCredentials(): array
    {
        $credentials = [
            'identifier',
            'password',
            'csrf_token'
        ];

        $credentials['identifier'] = $this->request->getBodyParam(SecurityAttributes::REQUEST_IDENTIFIER);
        $credentials['password'] = $this->request->getBodyParam(SecurityAttributes::REQUEST_PASSWORD);
        $credentials['csrf_token'] = $this->request->getBodyParam(SecurityAttributes::REQUEST_CSRF, '');

        return $credentials;
    }
}