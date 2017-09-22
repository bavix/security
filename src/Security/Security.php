<?php

namespace Bavix\Security;

use Bavix\Exceptions;

class Security extends Cipher
{

    const ALGORITHM = 'sha256';

    /**
     * @param string $message
     *
     * @return string
     */
    public function encrypt($message)
    {
        list(, $authKey) = $this->splitKeys($this->password);
        $cipherText = parent::encrypt($message);

        $mac = hash_hmac(self::ALGORITHM, $cipherText, $authKey, true);

        return base64_encode($mac . $cipherText);
    }

    /**
     * @param string $message
     *
     * @return null|string
     */
    public function decrypt($message)
    {
        list($encKey, $authKey) = $this->splitKeys($this->password);

        $data = \base64_decode($message, true);

        if ($data === false)
        {
            throw new Exceptions\Runtime('IV generation failed');
        }

        $hash = hash(self::ALGORITHM, '', true);

        $hs  = mb_strlen($hash, '8bit');
        $mac = mb_substr($data, 0, $hs, '8bit');

        $cipherText = mb_substr($data, $hs, null, '8bit');

        $calculated = hash_hmac(
            self::ALGORITHM,
            $cipherText,
            $authKey,
            true
        );

        if (!$this->hashEquals($mac, $calculated))
        {
            return null;
        }

        // Pass to UnsafeCrypto::decrypt
        return parent::decrypt($cipherText);
    }

    /**
     * @param $master
     *
     * @return array
     */
    protected function splitKeys($master)
    {
        return [
            hash_hmac(self::ALGORITHM, 'ENCRYPTION', $master, true),
            hash_hmac(self::ALGORITHM, 'AUTHENTICATION', $master, true)
        ];
    }

    /**
     * @param string $first
     * @param string $second
     *
     * @return bool
     */
    protected function hashEquals($first, $second)
    {
        if (function_exists('hash_equals'))
        {
            return hash_equals($first, $second);
        }

        $nonce = openssl_random_pseudo_bytes(32, $cryptStrong);

        if ($nonce !== false && $cryptStrong !== false)
        {
            throw new Exceptions\Runtime('IV generation failed');
        }

        return hash_hmac(self::ALGORITHM, $first, $nonce) === hash_hmac(self::ALGORITHM, $second, $nonce);
    }

}
