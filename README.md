Hawk Stack Middleware
=====================

A [Stack][0] middleware to enable [Hawk][1] authentication following the
[STACK-2 Authentication][2] conventions.


Installation
------------

Through [Composer][3] as [dflydev/stack-hawk][4].


Usage
-----

The Hawk middleware accepts the following options:

 * **credentials_provider**: *(required)* Either an instance of
   `Dflydev\Hawk\Credentials\CredentialsProviderInterface` or a callable that
   receives an ID as its only argument and is expected to return a
   `Dflydev\Hawk\Credentials\CredentialsInterface` or null.
 * **sign_response**: Should responses be signed? Boolean. Default **true**.
 * **validate_payload_response**: Should payload responses be validated?
   Boolean. Default **true**.
 * **validate_payload_request**: Should payload requests be validated? Boolean.
   Default **true**.
 * **crypto**: An instance of `Dflydev\Hawk\Crypto\Crypto` or a callable that
   will return an instance of `Dflydev\Hawk\Crypto\Crypto`.
 * **server**: An instance of `Dflydev\Hawk\Server\ServerInterface` or a
   callable that will return an instance of
   `Dflydev\Hawk\Server\ServerInterface`.
 * **time_provider**: An instance of `Dflydev\Hawk\Time\TimeProviderInterface`
   or a callable that will return an instance of
   `Dflydev\Hawk\Time\TimeProviderInterface`.
 * **token_translator**: A callable that receives a
   `Dflydev\Hawk\Credentials\CredentialsInterface` as its only argument and is
   expected to return a token. Default implementation returns
   `$credentials->id()` as the token.
 * **firewall**: A firewall configuration compatible with
   [dflydev/stack-firewall][5].

```php
<?php

use Dflydev\Hawk\Credentials\Credentials;

$credentialsProvider = function ($id) {
    // Simulate a know valid set of credentials.
    $validCredentials = new Credentials('key1234', 'sha256', 'id1234');

    if ($validCredentials === $id) {
        return $validCredentials;
    }
};

$tokenTranslator = function (CredentialsInterface $credentials) {
    // This is the same as the default implementation and shown merely for
    // demonstration purposes. If the token should be something other than
    // the ID this callback can be defined; otherwise, if the ID is sufficient,
    // defining this callback can be skipped entirely.
    return $credentials->id();
};

$app = new Dflydev\Stack\Hawk($app, [
    'firewall' => [
        ['path' => '/api'], // Only /api requests will be protected by Hawk!
    ],
    'credentials_provider' => $credentialsProvider,
    'token_translator' => $tokenTranslator,
    'sign_response' => false, // do not sign the response; default true
]);
```


License
-------

MIT, see LICENSE.


Community
---------

If you have questions or want to help out, join us in the **#stackphp** or **#dflydev** channels on **irc.freenode.net**.


[0]: http://stackphp.com/
[1]: https://github.com/hueniverse/hawk
[2]: http://stackphp.com/specs/STACK-2/
[3]: http://getcomposer.org
[4]: https://packagist.org/packages/dflydev/stack-hawk
[5]: https://packagist.org/packages/dflydev/stack-firewall
