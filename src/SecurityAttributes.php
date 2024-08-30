<?php

namespace Luminar\Security;

class SecurityAttributes
{
    // Session Variables

    public const SESSION_ERROR = "auth_error";
    public const SESSION_LAST_IDENTIFIER = "auth_username";
    public const SESSION_LOGGED_BOOL = "logged";
    public const SESSION_IDENTIFIER = "identifier";
    public const SESSION_ROLES = "roles";

    // Request Variables
    public const REQUEST_IDENTIFIER = "__username";
    public const REQUEST_PASSWORD = "__password";
    public const REQUEST_CSRF = "__token";

    // Access Token Variables
    public const DATABASE_TOKEN = "token";
}