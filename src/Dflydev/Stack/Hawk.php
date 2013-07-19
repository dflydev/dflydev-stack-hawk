<?php

namespace Dflydev\Stack;

use Dflydev\Hawk\Crypto\Crypto;
use Dflydev\Hawk\Header\HeaderFactory;
use Dflydev\Hawk\Server\ServerBuilder;
use Dflydev\Hawk\Server\UnauthorizedException;
use Pimple;
use Symfony\Component\HttpFoundation\Request;
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
        $delegate = function () use ($request, $type, $catch) {
            return $this->app->handle($request, $type, $catch);
        };

        if (!$request->headers->has('authorization')) {
            // We are only interested in requests with a authorization header.
            return call_user_func($delegate);
        }

        try {
            $header = HeaderFactory::createFromString($request->headers->get('authorization'));
        } catch (NotHawkAuthorizationException $e) {
            // We are only interested in requests with a HAWK authorization header.
            return call_user_func($delegate);
        } catch (FieldValueParserException $e) {
            return (new Response)->setCode(400);
        }

        try {
            if (null !== $qs = $request->getQueryString()) {
                $qs = '?'.$qs;
            }

            $authenticationResponse = $server->authenticate(
                $request->getMethod(),
                $request->getHost(),
                $request->getPort(),
                $request->getBaseUrl().$request->getPathInfo().$qs,
                $request->getContentType(),
                $request->getContent(),
                $header
            );
        } catch (UnauthorizedException $e) {
            $response = (new Response)->setCode(401);

            $header = $e->getHeader();
            $response->headers->set($header->fieldName(), $header->fieldValue());

            return $response;
        }

        // Compatiblity with standard Stack authorization
        $request->attributes->set('token', $authenticationResponse->credentials()->id());

        // Hawk specific information
        $request->attributes->set('hawk.credentials', $authenticationResponse->credentials());
        $request->attributes->set('hawk.artifacts', $authenticationResponse->artifacts());

        $response = call_user_func($delegate);

        if ($this->container['sign_response']) {
            $header = $c['server']->createHeader(
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
        if (!isset($options['user_provider'])) {
            throw new \RuntimeException("No 'user_provider' callback or service specified");
        }

        if ($options['user_provider'] instanceof UserProviderInterface) {
            $c['user_provider'] = $options['user_provider'];
        } elseif (is_callable($options['user_provider'])) {
            $c['user_provider'] = $c->protect($c['user_provider']);
        } else {
            throw new \InvalidArgumentException(
                "The 'user_provider' must either be an instance of UserProviderInterface or it must be callable"
            );
        }

        unset($options['user_provider']);

        $c = new Pimple([
            'sign_response' => true,
        ]);

        $c['crypto'] = $c->share(function () {
            new Crypto;
        });

        $c['server'] = $c->share(function () use ($c) {
            $builder = (new ServerBuilder($c['user_provider']))
                ->setCrypto($c['crypto']);

            // TODO: We should do things here with other builder related options
            //       so that middleware users can customize how Hawk server works.

            return $builder->build();
        });

        foreach ($options as $name => $value) {
            if (in_array($name, ['crypto', 'server']) && is_callable($value)) {
                $c[$name] = $c->share($value);

                continue;
            }

            $c[$name] = $value;
        }

        return $c;
    }
}
