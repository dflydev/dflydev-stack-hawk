<?php

namespace common;

use Dflydev\Stack\Hawk;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Dflydev\Hawk\Credentials\Credentials;

abstract class TestCase extends \PHPUnit_Framework_TestCase
{
    protected $credentials;

    public function setUp()
    {
        $this->credentials = new Credentials('key1234', 'sha256', 'id1234');
    }

    protected function hawkify(HttpKernelInterface $app, array $config = [])
    {
        $config = array_merge([
            'credentials_provider' => function ($id) {
                if ($this->credentials->id() === $id) {
                    return $this->credentials;
                }
            }
        ], $config);

        return new Hawk($app, $config);
    }
}
