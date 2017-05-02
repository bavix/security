<?php

namespace Bavix\Security;

use Bavix\Exceptions;

class Security
{

    /**
     * @var string
     */
    protected $password;

    /**
     * @var string
     */
    protected $method;

    /**
     * Security constructor.
     *
     * @param string $password
     * @param string $method
     */
    public function __construct($password, $method = 'aes-256-cbc')
    {
        $this->password = $password;
        $this->method   = $method;
    }

    /**
     * @param string $data
     *
     * @return array
     */
    protected function salted($data)
    {
        $key = substr($data, 0, 32);
        $iv  = substr($data, 32, 16);

        return [$key, $iv];
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function encrypt($data)
    {

        $salt = \openssl_random_pseudo_bytes(8, $cryptStrong);

        if (false === $cryptStrong || false === $salt)
        {
            throw new Exceptions\Runtime('IV generation failed');
        }

        $salted = '';
        $dx     = '';

        while (strlen($salted) < 48)
        {
            $dx     = md5($dx . $this->password . $salt, true);
            $salted .= $dx;
        }

        list($key, $iv) = $this->salted($salted);
        $encryptedData = openssl_encrypt($data, $this->method, $key, OPENSSL_RAW_DATA, $iv);

        return base64_encode('baVix' . $salt . $encryptedData);
    }

    /**
     * @param string $data
     *
     * @return string
     */
    public function decrypt($data)
    {
        $data       = base64_decode($data);

        $salt       = substr($data, 5, 8);
        $encrypted  = substr($data, 13);
        $data00     = $this->password . $salt;

        $md5Hash    = [];
        $md5Hash[0] = md5($data00, true);
        $result     = $md5Hash[0];

        for ($i = 1; $i < 3; $i++)
        {
            $md5Hash[$i] = md5($md5Hash[$i - 1] . $data00, true);
            $result      .= $md5Hash[$i];
        }

        list($key, $iv) = $this->salted($result);

        return openssl_decrypt($encrypted, $this->method, $key, true, $iv);
    }

}
