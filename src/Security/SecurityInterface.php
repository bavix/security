<?php

namespace Bavix\Security;

interface SecurityInterface
{

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
