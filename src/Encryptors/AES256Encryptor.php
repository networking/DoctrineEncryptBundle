<?php

namespace Ambta\DoctrineEncryptBundle\Encryptors;

/**
 * Class for AES256 encryption.
 *
 * @author Victor Melnik <melnikvictorl@gmail.com>
 */
class AES256Encryptor implements EncryptorInterface
{
    final public const METHOD_NAME = 'AES-256';
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
    private $initializationVector = '';

    /**
     * {@inheritdoc}
     * @param string $suffix
     */
    public function __construct($key, private $suffix)
    {
        $this->secretKey = md5((string) $key);
        $this->encryptMethod = sprintf('%s-%s', self::METHOD_NAME, self::ENCRYPT_MODE);
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
