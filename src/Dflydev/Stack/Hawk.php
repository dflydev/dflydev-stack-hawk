<?php

namespace Dflydev\Stack;

use Dflydev\Hawk\Crypto\Crypto;
use Dflydev\Hawk\Header\HeaderFactory;
use Dflydev\Hawk\Server\ServerBuilder;
use Dflydev\Hawk\Server\UnauthorizedException;
use Pimple;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class Hawk implements HttpKernelInterface
{
    private $app;
    private $container;

    public function __construct(HttpKernelInterface $app, array $options = array())
    {
        $this->app = $app;
        $this->container = $this->setupContainer($options);
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        // The challenge callback is called if a 401 response is detected that
        // has a "WWW-Authenticate: Stack" header. This is per the Stack
        // Authentication and Authorization proposals. It is passed the existing
        // response object.
        $challenge = function (Response $response) {
            $response->headers->set('WWW-Authenticate', 'Hawk');

            return $response;
        };

        // The authenticate callback is called if the request has no Stack
        // authentication token but there is an authorization header. It is
        // passed an app we should delegate to (assuming we do not return
        // beforehand) and a boolean value indicating whether or not anonymous
        // requests should be allowed.
        $authenticate = function ($app, $anonymous) use ($request, $type, $catch, $challenge) {
            try {
                $header = HeaderFactory::createFromString(
                    'Authorization',
                    $request->headers->get('authorization')
                );
            } catch (NotHawkAuthorizationException $e) {
                if ($anonymous) {
                    // This is not a Hawk request but the firewall allows
                    // anonymous requests so we should wrap the application
                    // so that we might be able to challenge if authorization
                    // fails.
                    return (new WwwAuthenticateStackChallenge($app, $challenge))
                        ->handle($request, $type, $catch);
                }

                // Anonymous requests are not allowed so we should challenge
                // immediately.
                return call_user_func($challenge, (new Response)->setStatusCode(401));
            } catch (FieldValueParserException $e) {
                // Something horribly wrong has happened.
                return (new Response)->setStatusCode(400);
            }

            try {
                $payload = $this->container['validate_payload_request']
                    ? ($request->getMethod() !== 'GET' ? $request->getContent() : null)
                    : null;

                $authenticationResponse = $this->container['server']->authenticate(
                    $request->getMethod(),
                    $request->getHost(),
                    $request->getPort(),
                    $request->getRequestUri(),
                    $request->headers->get('content-type'),
                    $payload,
                    $header
                );
            } catch (UnauthorizedException $e) {
                $response = (new Response)->setStatusCode(401);
                $header = $e->getHeader();
                $response->headers->set($header->fieldName(), $header->fieldValue());

                return $response;
            }

            // Stack authentication compatibility.
            $request->attributes->set(
                'stack.authn.token',
                $this->container['token_translator']($authenticationResponse->credentials())
            );

            // Hawk specific information
            $request->attributes->set('hawk.credentials', $authenticationResponse->credentials());
            $request->attributes->set('hawk.artifacts', $authenticationResponse->artifacts());

            $response = $app->handle($request, $type, $catch);

            if ($this->container['sign_response']) {
                $options = [];
                if ($this->container['validate_payload_response']) {
                    $options['payload'] = $response->getContent();
                    $options['content_type'] = $response->headers->get('content-type');
                }

                $header = $this->container['server']->createHeader(
                    $authenticationResponse->credentials(),
                    $authenticationResponse->artifacts(),
                    $options
                );

                $response->headers->set($header->fieldName(), $header->fieldValue());
            }

            return $response;
        };

        return (new Firewall($this->app, [
                'challenge' => $challenge,
                'authenticate' => $authenticate,
                'firewall' => $this->container['firewall'],
            ]))
            ->handle($request, $type, $catch);
    }

    private function setupContainer(array $options = array())
    {
        if (!isset($options['credentials_provider'])) {
            throw new \RuntimeException("No 'credentials_provider' callback or service specified");
        }

        if ($options['credentials_provider'] instanceof UserProviderInterface ||
            is_callable($options['credentials_provider'])) {
            $credentialsProvider = $options['credentials_provider'];
        } else {
            throw new \InvalidArgumentException(
                "The 'credentials_provider' must either be an instance of UserProviderInterface or it must be callable"
            );
        }

        unset($options['credentials_provider']);

        $c = new Pimple([
            'sign_response' => true,
            'validate_payload_response' => true,
            'validate_payload_request' => true,
            'firewall' => [],
        ]);

        $c['crypto'] = $c->share(function () {
            return new Crypto;
        });

        $c['server'] = $c->share(function () use ($c, $credentialsProvider) {
            $builder = (new ServerBuilder($credentialsProvider))
                ->setCrypto($c['crypto']);

            if (isset($c['time_provider'])) {
                $builder->setTimeProvider($c['time_provider']);
            }

            return $builder->build();
        });

        $c['token_translator'] = $c->protect(function ($credentials) {
            return $credentials->id();
        });

        foreach ($options as $name => $value) {
            if (in_array($name, ['crypto', 'server', 'time_provider', 'token_translator'])) {
                if (is_callable($value)) {
                    $c[$name] = $c->share($value);
                } else {
                    $c[$name] = $c->share(function () use ($value) {
                        return $value;
                    });
                }

                continue;
            }

            $c[$name] = $value;
        }

        return $c;
    }
}
