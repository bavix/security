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
        $authKey    = $this->authen($this->password);
        $cipherText = parent::encrypt($message);

        $mac = \hash_hmac(self::ALGORITHM, $cipherText, $authKey, true);

        return \base64_encode($mac . $cipherText);
    }

    /**
     * @param string $message
     *
     * @return null|string
     */
    public function decrypt($message)
    {
        $authKey = $this->authen($this->password);
        $data    = \base64_decode($message, true);

        if ($data === false)
        {
            throw new Exceptions\Runtime('IV generation failed');
        }

        $hash = \hash(self::ALGORITHM, '', true);

        $hs  = \mb_strlen($hash, '8bit');
        $mac = \mb_substr($data, 0, $hs, '8bit');

        $cipherText = \mb_substr($data, $hs, null, '8bit');

        $calculated = \hash_hmac(
            self::ALGORITHM,
            $cipherText,
            $authKey,
            true
        );

        if (!\hash_equals($mac, $calculated))
        {
            return null;
        }

        return parent::decrypt($cipherText);
    }

    /**
     * @param string $master
     *
     * @return string
     */
    protected function authen($master)
    {
        return \hash_hmac(self::ALGORITHM, 'AUTHENTICATION', $master, true);
    }

}
