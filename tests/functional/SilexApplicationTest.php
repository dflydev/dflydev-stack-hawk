<?php

namespace functional;

use common\TestCase;
use Dflydev\Hawk\Credentials\Credentials;
use Dflydev\Hawk\Header\HeaderFactory;
use Dflydev\Hawk\Nonce\NonceProviderInterface;
use Dflydev\Hawk\Time\TimeProviderInterface;
use Dflydev\Stack\Hawk;
use Pimple;
use Silex\Application;
use Stack\Inline;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\HttpKernel\HttpKernelInterface;

class SilexApplicationTest extends TestCase
{
    /** @test */
    public function shouldIgnoreRequestsNotFirewalled()
    {
        $app = $this->hawkify($this->createTestApp(), ['firewall' => [
            ['path' => '/foo'],
        ]]);

        $client = new Client($app);

        $client->request('GET', '/');
        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldNotChallengeForUnprotectedResourceNoHeader()
    {
        $app = $this->hawkify($this->createTestApp(), ['firewall' => [
            ['path' => '/', 'anonymous' => true],
        ]]);

        $client = new Client($app);

        $client->request('GET', '/');
        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldChallengeForProtectedResourceNoHeader()
    {
        $app = $this->hawkify($this->createTestApp(), ['firewall' => [
            ['path' => '/', 'anonymous' => true],
        ]]);

        $client = new Client($app);

        $client->request('GET', '/protected/resource');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Hawk', $client->getResponse()->headers->get('www-authenticate'));
    }

    /**
     * @test
     */
    public function shouldGetExpectedToken()
    {
        $timeProvider = new MockTimeProvider(56789);
        $app = $this->hawkify($this->createTestApp(), ['time_provider' => $timeProvider]);

        $hawkClient = (new \Dflydev\Hawk\Client\ClientBuilder)
            ->setTimeProvider($timeProvider)
            ->build();

        $hawkRequest = $hawkClient->createRequest(
            $this->credentials,
            'http://localhost/protected/token',
            'GET',
            array()
        );

        $client = new Client($app);

        $client->request('GET', '/protected/token', [], [], ['HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue()]);
        $this->assertEquals($this->credentials->id(), $client->getResponse()->getContent());
    }

    /**
     * @test
     * @dataProvider protectedAndUnprotectedResources
     */
    public function shouldChallengeForInvalidHeader($resource)
    {
        $app = $this->hawkify($this->createTestApp());

        $client = new Client($app);

        $client->request(
            'GET',
            $resource,
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => 'Hawk'
            ]
        );
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Hawk error="Missing attributes"', $client->getResponse()->headers->get('www-authenticate'));
    }

    /**
     * @test
     * @dataProvider protectedAndUnprotectedResources
     */
    public function shouldAllowAccessToResource($resource, $expectedContent)
    {
        $timeProvider = new MockTimeProvider(56789);
        $app = $this->hawkify($this->createTestApp(), ['time_provider' => $timeProvider]);

        $hawkClient = (new \Dflydev\Hawk\Client\ClientBuilder)
            ->setTimeProvider($timeProvider)
            ->build();

        $hawkRequest = $hawkClient->createRequest(
            $this->credentials,
            'http://localhost'.$resource,
            'GET',
            array()
        );

        $client = new Client($app);

        $client->request('GET', $resource, [], [], ['HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue()]);
        $this->assertEquals($expectedContent, $client->getResponse()->getContent());

        $authenticatedResponse = $hawkClient->authenticate(
            $this->credentials,
            $hawkRequest,
            $client->getResponse()->headers->get('Server-Authorization'),
            [
                'payload' => $client->getResponse()->getContent(),
                'content_type' => $client->getResponse()->headers->get('content-type'),
            ]
        );

        $this->assertTrue($authenticatedResponse);
    }

    /**
     * @test
     * @dataProvider protectedAndUnprotectedResources
     */
    public function shouldAllowAccessToResourceNoSignedResponse($resource, $expectedContent)
    {
        $timeProvider = new MockTimeProvider(56789);
        $app = $this->hawkify($this->createTestApp(), [
            'time_provider' => $timeProvider,
            'sign_response' => false,
        ]);

        $hawkClient = (new \Dflydev\Hawk\Client\ClientBuilder)
            ->setTimeProvider($timeProvider)
            ->build();

        $hawkRequest = $hawkClient->createRequest(
            $this->credentials,
            'http://localhost'.$resource,
            'GET',
            array()
        );

        $client = new Client($app);

        $client->request('GET', $resource, [], [], ['HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue()]);
        $this->assertEquals($expectedContent, $client->getResponse()->getContent());
        $this->assertFalse($client->getResponse()->headers->has('Server-Authorization'));
    }

    /**
     * @test
     */
    public function shouldConvertWwwAuthenticateStackToHawk()
    {
        $authz = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            $response = (new Response)->setStatusCode(401);
            $response->headers->set('WWW-Authenticate', 'Stack');
            return $response;
        };

        $app = $this->hawkify(new Inline($this->createTestApp(), $authz));

        $client = new Client($app);

        $client->request('GET', '/');
        $this->assertEquals('Hawk', $client->getResponse()->headers->get('WWW-Authenticate'));
    }

    /**
     * @test
     */
    public function shouldNotClobberExistingToken()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // Hawk should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $app = new Inline($this->hawkify($this->createTestApp()), $authnMiddleware);

        $client = new Client($app);

        $client->request('GET', '/protected/token');
        $this->assertEquals('foo', $client->getResponse()->getContent());
    }

    /**
     * @test
     */
    public function shouldChallengeOnAuthorizationEvenIfOtherMiddlewareAuthenticated()
    {
        $authnMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // We are going to claim that we authenticated...
            $request->attributes->set('stack.authn.token', 'foo');

            // Hawk should actually capture the WWW-Authenticate: Stack response
            // and challenge on its own.
            return $app->handle($request, $type, $catch);
        };

        $authzMiddleware = function(
            HttpKernelInterface $app,
            Request $request,
            $type = HttpKernelInterface::MASTER_REQUEST,
            $catch = true
        ) {
            // Simulate Authorization failure by returning 401 status
            // code with WWW-Authenticate: Stack.
            $response = (new Response)->setStatusCode(401);
            $response->headers->set('WWW-Authenticate', 'Stack');
            return $response;
        };

        $app = new Inline($this->hawkify(new Inline($this->createTestApp(), $authzMiddleware)), $authnMiddleware);

        $client = new Client($app);

        $client->request('GET', '/protected/token');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Hawk', $client->getResponse()->headers->get('www-authenticate'));
    }

    /**
     * @test
     */
    public function shouldPassTentTestVectorsAppRequest()
    {
        $timeProvider = new MockTimeProvider(1368996800);
        $nonceProvider = new MockNonceProvider('3yuYCD4Z');
        $credentials = new Credentials('HX9QcbD-r3ItFEnRcAuOSg', 'sha256', 'exqbZWtykFZIh2D7cXi9dA');

        $app = $this->hawkify($this->createTestApp(), [
            'validate_payload_response' => false, // this test actually has no payload validaton
            'time_provider' => $timeProvider,
            'credentials_provider' => function ($id) use ($credentials) {
                if ($credentials->id() === $id) {
                    return $credentials;
                }
            }
        ]);

        $hawkClient = (new \Dflydev\Hawk\Client\ClientBuilder)
            ->setTimeProvider($timeProvider)
            ->setNonceProvider($nonceProvider)
            ->build();

        $hawkRequest = $hawkClient->createRequest(
            $credentials,
            'https://example.com/posts',
            'POST',
            [
                'payload' => '{"type":"https://tent.io/types/status/v0#"}',
                'content_type' => 'application/vnd.tent.post.v0+json',
                'app' => 'wn6yzHGe5TLaT-fvOPbAyQ',
            ]
        );

        $expectedHeader = HeaderFactory::createFromString(
            'Authorization',
            'Hawk id="exqbZWtykFZIh2D7cXi9dA", mac="2sttHCQJG9ejj1x7eCi35FP23Miu9VtlaUgwk68DTpM=", ts="1368996800", nonce="3yuYCD4Z", hash="neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU=", app="wn6yzHGe5TLaT-fvOPbAyQ"'
        );

        $this->assertEquals($expectedHeader->fieldName(), $hawkRequest->header()->fieldName());
        $this->assertEquals($expectedHeader->attributes(), $hawkRequest->header()->attributes());

        $client = new Client($app);

        $client->request(
            'POST',
            'https://example.com/posts',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue(),
                'CONTENT_TYPE' => 'application/vnd.tent.post.v0+json',
            ],
            '{"type":"https://tent.io/types/status/v0#"}'
        );

        $this->assertEquals('{"type":"https://tent.io/types/status/v0#"}', $client->getResponse()->getContent());

        $this->assertEquals(
            'Hawk mac="lTG3kTBr33Y97Q4KQSSamu9WY/mOUKnZzq/ho9x+yxw="',
            $client->getResponse()->headers->get('Server-Authorization')
        );

        $authenticatedResponse = $hawkClient->authenticate(
            $credentials,
            $hawkRequest,
            $client->getResponse()->headers->get('Server-Authorization'),
            [
                //'payload' => $client->getResponse()->getContent(),
                //'content_type' => $client->getResponse()->headers->get('content-type'),
            ]
        );

        $this->assertTrue($authenticatedResponse);
    }


    /**
     * @test
     */
    public function shouldPassTentTestVectorsRelationshipRequest()
    {
        $timeProvider = new MockTimeProvider(1368996800);
        $nonceProvider = new MockNonceProvider('3yuYCD4Z');
        $credentials = new Credentials('HX9QcbD-r3ItFEnRcAuOSg', 'sha256', 'exqbZWtykFZIh2D7cXi9dA');

        $app = $this->hawkify($this->createTestApp(), [
            'validate_payload_request' => false,
            'time_provider' => $timeProvider,
            'credentials_provider' => function ($id) use ($credentials) {
                if ($credentials->id() === $id) {
                    return $credentials;
                }
            }
        ]);

        $hawkClient = (new \Dflydev\Hawk\Client\ClientBuilder)
            ->setTimeProvider($timeProvider)
            ->setNonceProvider($nonceProvider)
            ->build();

        $hawkRequest = $hawkClient->createRequest(
            $credentials,
            'https://example.com/posts',
            'POST',
            [
            ]
        );

        $expectedHeader = HeaderFactory::createFromString(
            'Authorization',
            'Hawk id="exqbZWtykFZIh2D7cXi9dA", mac="OO2ldBDSw8KmNHlEdTC4BciIl8+uiuCRvCnJ9KkcR3Y=", ts="1368996800", nonce="3yuYCD4Z"'
        );

        $this->assertEquals($expectedHeader->fieldName(), $hawkRequest->header()->fieldName());
        $this->assertEquals($expectedHeader->attributes(), $hawkRequest->header()->attributes());

        $client = new Client($app);

        $client->request(
            'POST',
            'https://example.com/posts',
            [],
            [],
            [
                'HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue(),
                'CONTENT_TYPE' => 'application/vnd.tent.post.v0+json',
            ],
            '{"type":"https://tent.io/types/status/v0#"}'
        );

        $this->assertEquals(
            'Hawk mac="LvxASIZ2gop5cwE2mNervvz6WXkPmVslwm11MDgEZ5E=", hash="neQFHgYKl/jFqDINrC21uLS0gkFglTz789rzcSr7HYU="',
            $client->getResponse()->headers->get('Server-Authorization')
        );

        $authenticatedResponse = $hawkClient->authenticate(
            $credentials,
            $hawkRequest,
            $client->getResponse()->headers->get('Server-Authorization'),
            [
                'payload' => $client->getResponse()->getContent(),
                'content_type' => $client->getResponse()->headers->get('content-type'),
            ]
        );

        $this->assertTrue($authenticatedResponse);
    }

    protected function createTestApp()
    {
        $app = new Application;
        $app['exception_handler']->disable();

        $app->get('/', function () {
            return 'Root.';
        });

        $app->get('/protected/resource', function () {
            return 'Protected Resource.';
        });

        $app->get('/protected/token', function (Request $request) {
            return $request->attributes->get('stack.authn.token');
        });

        $app->post('/posts', function () {
            $response = (new Response)
                ->setStatusCode(200)
                ->setContent('{"type":"https://tent.io/types/status/v0#"}');

            $response->headers->set('Content-Type', 'application/vnd.tent.post.v0+json');

            return $response;
        });

        // Simple Silex middleware to always let certain requests go through
        // and to always throw 401 responses in all other cases *unless*
        // stack.authn.token has been set correctly.
        $app->before(function (Request $request) {
            if (in_array($request->getRequestUri(), array('/'))) {
                return;
            }

            if (!$request->attributes->has('stack.authn.token')) {
                $response = (new Response)->setStatusCode(401);
                $response->headers->set('WWW-Authenticate', 'Stack');

                return $response;
            }
        });

        return $app;
    }

    public function protectedAndUnprotectedResources()
    {
        return [
            ['/', 'Root.'],
            ['/protected/resource', 'Protected Resource.'],
        ];
    }
}

class MockNonceProvider implements NonceProviderInterface
{
    private $nonce;

    public function __construct($nonce)
    {
        $this->nonce = $nonce;
    }

    public function createNonce()
    {
        return $this->nonce;
    }
}

class MockTimeProvider implements TimeProviderInterface
{
    private $timestamp;

    public function __construct($timestamp)
    {
        $this->timestamp = $timestamp;
    }

    public function createTimestamp()
    {
        return $this->timestamp;
    }
}
