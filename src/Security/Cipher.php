<?php

namespace Bavix\Security;

use Bavix\Exceptions;

class Cipher implements SecurityInterface
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
     * Cipher constructor.
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
     * @param string $message
     *
     * @return string
     */
    public function encrypt($message)
    {

        $nonceSize = \openssl_cipher_iv_length($this->method);
        $nonce     = \openssl_random_pseudo_bytes($nonceSize, $cryptStrong);

        if (false === $cryptStrong || false === $nonce)
        {
            throw new Exceptions\Runtime('IV generation failed');
        }

        $cipherText = \openssl_encrypt(
            $message,
            $this->method,
            $this->password,
            OPENSSL_RAW_DATA,
            $nonce
        );

        return \base64_encode($nonce . $cipherText);
    }

    /**
     * @param string $message
     *
     * @return string
     */
    public function decrypt($message)
    {
        $data = \base64_decode($message, true);

        if ($data === false)
        {
            throw new Exceptions\Invalid('Invalid `message` on decrypt');
        }

        $nonceSize  = \openssl_cipher_iv_length($this->method);
        $nonce      = \mb_substr($data, 0, $nonceSize, '8bit');
        $cipherText = \mb_substr($data, $nonceSize, null, '8bit');

        $plaintext = \openssl_decrypt(
            $cipherText,
            $this->method,
            $this->password,
            OPENSSL_RAW_DATA,
            $nonce
        );

        return $plaintext;
    }

}
