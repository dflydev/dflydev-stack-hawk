<?php

namespace functional;

use common\TestCase;
use Dflydev\Hawk\Time\TimeProviderInterface;
use Dflydev\Stack\Hawk;
use Pimple;
use Silex\Application;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Client;

class SilexApplicationTest extends TestCase
{
    /** @test */
    public function shouldNotChallengeForUnprotectedResourceNoHeader()
    {
        $app = $this->hawkify($this->createTestApp());

        $client = new Client($app);

        $client->request('GET', '/');
        $this->assertEquals('Root.', $client->getResponse()->getContent());
    }

    /** @test */
    public function shouldChallengeForProtectedResourceNoHeader()
    {
        $app = $this->hawkify($this->createTestApp());

        $client = new Client($app);

        $client->request('GET', '/protected/resource');
        $this->assertEquals(401, $client->getResponse()->getStatusCode());
        $this->assertEquals('Hawk', $client->getResponse()->headers->get('www-authenticate'));
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

        $this->assertEquals('Authorization', $hawkRequest->header()->fieldName());

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

        $this->assertEquals('Authorization', $hawkRequest->header()->fieldName());

        $client = new Client($app);

        $client->request('GET', $resource, [], [], ['HTTP_AUTHORIZATION' => $hawkRequest->header()->fieldValue()]);
        $this->assertEquals($expectedContent, $client->getResponse()->getContent());
        $this->assertFalse($client->getResponse()->headers->has('Server-Authorization'));
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

        // Simple Silex middleware to always let certain requests go through
        // and to always throw 401 responses in all other cases *unless*
        // stack.authentication.token has been set correctly.
        $app->before(function (Request $request) {
            if (in_array($request->getRequestUri(), array('/'))) {
                return;
            }

            if (!$request->attributes->has('stack.authentication.token')) {
                return (new Response)->setStatusCode(401);
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
