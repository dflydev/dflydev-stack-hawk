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
    public function __construct(HttpKernelInterface $app, array $options = array())
    {
        $this->app = $app;
        $this->container = $this->setupContainer($options);
    }

    public function handle(Request $request, $type = HttpKernelInterface::MASTER_REQUEST, $catch = true)
    {
        // The challenge callback is used to massage the Response per Stack
        // Authentication and Authorization conventions. It will be called
        // by authenticate() if a 401 response is detected that has a
        // "WWW-Authenticate: Stack" header.
        $challenge = function (Response $response) {
            $response->headers->set('WWW-Authenticate', 'Hawk');

            return $response;
        };

        $firewalls = isset($this->container['firewalls'])
            ? $this->container['firewalls']
            : [];

        // Use a helper function to work with Stack conventions for firewall
        // configuration and authorization delegation.
        list ($isResponse, $value, $firewall) = \Stack\Security\authenticate(
            $this->app,
            $challenge,
            $firewalls,
            $request,
            $type,
            $catch
        );

        if ($isResponse) {
            // If our value represents a response we should immediately
            // pass it back.
            return $value;
        }

        // Otherwise, the value represents a delegate.
        $delegate = $value;


        //
        // At this point we know for certain that Hawk authentication is
        // expected to be possible for this request *and* that this request
        // has an authorization header.
        //

        try {
            $header = HeaderFactory::createFromString('Authorization', $request->headers->get('authorization'));
        } catch (NotHawkAuthorizationException $e) {
            if ($firewall['anonymous']) {
                // If anonymous requests are allowed by our firewall we should
                // hand off to the delegate.
                return call_user_func($delegate);
            }

            // Otherwise, we should challenge immediately.
            // We use $challenge to be slightly more DRY.
            $response = (new Response)->setStatusCode(401);
            call_user_func($challenge, $response);

            return $response;
        } catch (FieldValueParserException $e) {
            // Something horribly wrong has happened.
            return (new Response)->setStatusCode(400);
        }

        try {
            $authenticationResponse = $this->container['server']->authenticate(
                $request->getMethod(),
                $request->getHost(),
                $request->getPort(),
                $request->getRequestUri(),
                $request->getContentType(),
                $request->getContent() ?: null,
                $header
            );
        } catch (UnauthorizedException $e) {
            $response = (new Response)->setStatusCode(401);

            $header = $e->getHeader();
            $response->headers->set($header->fieldName(), $header->fieldValue());

            return $response;
        }

        // Compatiblity with standard Stack authorization
        $request->attributes->set('stack.authentication.token', $authenticationResponse->credentials()->id());

        // Hawk specific information
        $request->attributes->set('hawk.credentials', $authenticationResponse->credentials());
        $request->attributes->set('hawk.artifacts', $authenticationResponse->artifacts());

        $response = call_user_func($delegate);

        if ($this->container['sign_response']) {
            $header = $this->container['server']->createHeader(
                $authenticationResponse->credentials(),
                $authenticationResponse->artifacts(),
                array(
                    'payload' => $response->getContent(),
                    'content_type' => $response->headers->get('content-type'),
                )
            );

            $response->headers->set($header->fieldName(), $header->fieldValue());
        }

        return $response;
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

        foreach ($options as $name => $value) {
            if (in_array($name, ['crypto', 'server', 'time_provider'])) {
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
