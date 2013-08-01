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
        // The challenge callback is called to massage the Response per Stack
        // Authentication and Authorization conventions. It will be called
        // if a 401 response is detected that has a "WWW-Authenticate: Stack"
        // header.
        $challenge = function (Response $response) {
            $response->headers->set('WWW-Authenticate', 'Hawk');

            return $response;
        };

        // The authenticate callback is called if the request could potentially
        // contain authentication credentials for us to authentication. This
        // means that there is no Stack authentication token yet but there is an
        // authorization header. We are passed the app that we should delegate
        // to in the event that we do not return something on our own.
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

        return (new FirewallAuthentication($this->app, [
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

class FirewallAuthentication implements HttpKernelInterface
{
    private $app;
    private $firewall;
    private $options;

    public function __construct(HttpKernelInterface $app, array $options = [])
    {
        $this->app = $app;
        $this->firewall = $options['firewall'];
        unset($options['firewall']);
        $this->options = $options;
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $firewall = static::matchFirewall($request, $this->firewall);

        if (null === $firewall) {
            // If no firewall is matched we can delegate immediately.
            return $this->app->handle($request, $type, $catch);
        }

        return (new Authentication($this->app, array_merge($this->options, ['anonymous' => $firewall['anonymous']])))
            ->handle($request, $type, $catch);
    }

    /**
     * Left public currently so we can test this by itself; eventually would
     * maybe like to make this a service that can be swapped out via
     * configuration? Not sure what to do with it, really.
     */
    public static function matchFirewall(Request $request, array $firewalls)
    {
        if (!$firewalls) {
            // By default we should firewall the root request and not allow
            // anonymous requests. (will force challenge immediately)
            $firewalls = [
                ['path' => '/']
            ];
        }

        $sortedFirewalls = [];
        foreach ($firewalls as $firewall) {
            if (!isset($firewall['anonymous'])) {
                $firewall['anonymous'] = false;
            }

            if (isset($sortedFirewalls[$firewall['path']])) {
                throw new \InvalidArgumentException("Path '".$firewall['path']."' specified more than one time.");
            }

            $sortedFirewalls[$firewall['path']] = $firewall;
        }

        // We want to sort things by more specific paths first. This will
        // ensure that for instance '/' is never captured before any other
        // firewalled paths.
        krsort($sortedFirewalls);

        foreach ($sortedFirewalls as $path => $firewall) {
            if (0 === strpos($request->getPathInfo(), $path)) {
                return $firewall;
            }
        }

        return null;
    }
}

class Authentication implements HttpKernelInterface
{
    private $app;
    private $challenge;
    private $authenticate;
    private $anonymous;

    public function __construct(HttpKernelInterface $app, array $options = [])
    {
        $this->app = $app;

        if (!isset($options['challenge'])) {
            $options['challenge'] = function (Response $response) {
                // noop
            };
        }

        if (!isset($options['authenticate'])) {
            throw new \InvalidArgumentException("The 'authenticate' configuration is required");
        }

        $this->challenge = $options['challenge'];
        $this->authenticate = $options['authenticate'];
        $this->anonymous = $options['anonymous'];
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        if ($request->attributes->has('stack.authn.token')) {
            // If the request already has a Stack authentication token we
            // should wrap the application so that it has the option to
            // challenge if we get a 401 WWW-Authenticate: Stack response.
            //
            // Delegate immediately.
            return (new WwwAuthenticateStackChallenge($this->app, $this->challenge))
                ->handle($request, $type, $catch);
        }

        if ($request->headers->has('authorization')) {
            // If we have an authorization header we should try and authenticate
            // the request.
            return call_user_func($this->authenticate, $this->app, $this->anonymous);
        }

        if ($this->anonymous) {
            // If anonymous requests are allowed we should wrap the application
            // so that it has the option to challenge if we get a 401
            // WWW-Authenticate: Stack response.
            //
            // Delegate immediately.
            return (new WwwAuthenticateStackChallenge($this->app, $this->challenge))
                ->handle($request, $type, $catch);
        }

        // Since we do not allow anonymous requests we should challenge
        // immediately.
        return call_user_func($this->challenge, (new Response)->setStatusCode(401));
    }
}

class WwwAuthenticateStackChallenge implements HttpKernelInterface
{
    private $app;
    private $challenge;

    public function __construct(HttpKernelInterface $app, $challenge = null)
    {
        $this->app = $app;
        $this->challenge = $challenge ?: function (Response $response) {
            return (new Response('Authentication not possible', 403));
        };
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        $response = $this->app->handle($request, $type, $catch);

        if ($response->getStatusCode()==401 && $response->headers->get('WWW-Authenticate') === 'Stack') {
            // By convention, we look for 401 response that has a WWW-Authenticate with field value of
            // Stack. In that case, we should pass the response to the delegatee's challenge callback.
            $response = call_user_func($this->challenge, $response);
        }

        return $response;
    }
}
