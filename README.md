# Luminar Security

![Tests Status](https://img.shields.io/github/actions/workflow/status/luminar-organization/security/test.yml?label=Tests)

Luminar Security is a PHP library designed to provide a comprehensive set of security utilities and components for building secure web applications. It includes modules for authentication, encryption, hashing, protection against common web vulnerabilities, and more.

## Features

- **Authentication**: Form Login, access tokens, login link, and utility functions.
- **Encryption**: Support for AES256, Base64, RSA, and XOR encryption methods.
- **Hashing**: Provides multiple hashing algorithms like Argon2i, Argon2id, Bcrypt, Hmac, MD5, SHA1, and SHA256
- **Protection**: Protection against CSRF, XSS, XML attacks, ClickJacking.
- **Exceptions**: Custom exceptions for handling security-related errors.

## Installation

To install the Luminar Security library, you can use Composer:

```shell
composer require luminar-organization/security
```

## Usage

### Authentication

Example of using form-based authentication

```php
use Luminar\Security\Authentication\FormLogin;
use Luminar\Core\Config\Config;
use Luminar\Http\Request;
use Luminar\Http\Managers\SessionManager;
use Luminar\Database\Connection\Connection;

$connection = new Connection("mysql:host=localhost;dbname=luminar-test", 'root');
$config = new Config("PATH TO YOUR CONFIGS LOCATION");
$sessionManager = new SessionManager();
$request = new Request();

// Form Login can throw these exceptions:
// - ConfigException (invalid configuration)
// - InvalidCredentials (invalid credentials)
// - SuccessAuthentication (on success)
new FormLogin($request, $config, $sessionManager, $connection);

```

### Encryption

Example of encrypting data with AES256
```php
use Luminar\Security\Encryption\AES256;

$AES256 = new AES256();

$data = "Hello World!";
$secretKey = 'my_secret_key';
$secretVi = 'my_secret_vi';

$encrypted = $AES256->encrypt($data, $secretKey, $secretVi);
$decrypted = $AES256->decrypt($encrypted, $secretKey, $secretVi);
```

## Testing
The library includes a comprehensive set of tests to ensure its security features are working correctly.
To run the tests, use PHPUnit:
```shell
composer run test
```

## Contributing

Checkout our [core repository CONTRIBUTING.md](https://github.com/luminar-organization/core/)

## License
This project is licendes under the MIT License - se the [License](LICENSE) file for details

## Support

If you have any questions or need help, feel free to open an issue in the GitHub Repository.

