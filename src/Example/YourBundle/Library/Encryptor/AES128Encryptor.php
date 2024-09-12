<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

/**
 * Class for AES128 encryption.
 */
class AES128Encryptor implements EncryptorInterface
{
    final public const ENCRYPT_NAME = 'AES-128';
    final public const ENCRYPT_MODE = 'ECB';

    /**
     * @var string
     */
    private $secretKey;

    /**
     * @var string
     */
    private $encryptMethod;

    /**
     * @var string
     */
    private $initializationVector;

    /**
     * {@inheritdoc}
     * @param string $suffix
     */
    public function __construct($key, private $suffix)
    {
        $this->secretKey = md5((string) $key);
        $this->encryptMethod = sprintf('%s-%s', self::ENCRYPT_NAME, self::ENCRYPT_MODE);
        $this->initializationVector = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length($this->encryptMethod)
        );
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        if (is_string($data)) {
            return trim(base64_encode(openssl_encrypt(
                $data,
                $this->encryptMethod,
                $this->secretKey,
                0,
                $this->initializationVector
            ))).$this->suffix;
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
                $this->encryptMethod,
                $this->secretKey,
                0,
                $this->initializationVector
            ));
        }

        return $data;
    }
}
