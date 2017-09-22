<?php

namespace Bavix\Security;

interface SecurityInterface
{

    /**
     * SecurityInterface constructor.
     *
     * @param string $password
     * @param string $method
     */
    public function __construct($password, $method = 'aes-256-cbc');

    /**
     * @param string $message
     *
     * @return string
     */
    public function encrypt($message);

    /**
     * @param string $message
     *
     * @return string
     */
    public function decrypt($message);

}
