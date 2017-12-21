<?php

namespace Bavix\Security;

class Password
{

    /**
     * @var string
     */
    protected $algo;

    /**
     * @var array
     */
    protected $options;

    /**
     * Password constructor.
     *
     * @param array $options
     */
    public function __construct(string $algo, array $options = null)
    {
        $this->algo    = $algo;
        $this->options = $options;

        if (!$options)
        {
            $this->options = [
                'cost' => 12
            ];
        }
    }

    /**
     * @param string $password
     *
     * @return bool|string
     */
    public function hash(string $password)
    {
        return \password_hash(
            $password,
            $this->algo,
            $options
        );
    }

    /**
     * @param string $password
     *
     * @return bool
     */
    public function verify(string $password)
    {
        return \password_verify(
            $password,
            $this->algo
        );
    }

}
