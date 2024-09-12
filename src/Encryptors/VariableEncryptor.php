<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

/**
 * Class for variable encryption.
 *
 * @author Victor Melnik <melnikvictorl@gmail.com>
 */
class VariableEncryptor implements EncryptorInterface
{
    const ENCRYPT_METHOD = 'aes-256-ecb';

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $suffix;

    /**
     * @var string
     */
    private $initializationVector;

    /**
     * {@inheritdoc}
     */
    public function __construct($key, $suffix)
    {
        $this->secretKey = md5($key);
        $this->suffix = $suffix;
        $this->initializationVector = false;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        if (is_string($data)) {
            return trim(base64_encode(openssl_encrypt(
                $data,
                self::ENCRYPT_METHOD,
                $this->secretKey,
                0,
                $this->initializationVector
            ))).$this->suffix;
        }

        /*
         * Use ROT13 which is an simple letter substitution cipher with some additions
         * Not the safest option but it makes it alot harder for the attacker
         *
         * Not used, needs improvement or other solution
         */
        if (is_integer($data)) {
            //Not sure
        }

        return $data;
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        if (is_string($data)) {
            $data = str_replace($this->suffix, '', $data);

            return trim(openssl_decrypt(
                base64_decode($data),
                self::ENCRYPT_METHOD,
                $this->secretKey,
                0,
                $this->initializationVector
            ));
        }

        return $data;
    }
}
