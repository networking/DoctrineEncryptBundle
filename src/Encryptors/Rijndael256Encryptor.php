<?php
namespace Ambta\DoctrineEncryptBundle\Encryptors;

if(function_exists('mcrypt_create_iv')){
    /**
     * Class for AES256 encryption
     *
     * @author Victor Melnik <melnikvictorl@gmail.com>
     */
    class Rijndael256Encryptor implements EncryptorInterface{

        /**
         * @var string
         */
        private $secretKey;

        /**
         * @var string
         */
        private $initializationVector;

        /**
         * {@inheritdoc}
         */
        public function __construct($key, $suffix) {
            $this->secretKey = md5((string) $key);
            $this->initializationVector = mcrypt_create_iv(
                mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB),
                MCRYPT_RAND
            );
        }

        /**
         * {@inheritdoc}
         */
        public function encrypt($data) {
            return trim(base64_encode((string) mcrypt_encrypt(
                MCRYPT_RIJNDAEL_256,
                $this->secretKey,
                $data,
                MCRYPT_MODE_ECB,
                $this->initializationVector
            )));
        }

        /**
         * {@inheritdoc}
         */
        public function decrypt($data) {
            return trim((string) mcrypt_decrypt(
                MCRYPT_RIJNDAEL_256,
                $this->secretKey,
                base64_decode($data),
                MCRYPT_MODE_ECB,
                $this->initializationVector
            ));
        }
    }
}else{
    class_alias(
        AES256Encryptor::class,
        __NAMESPACE__.'\Rijndael256Encryptor'
    );

}
