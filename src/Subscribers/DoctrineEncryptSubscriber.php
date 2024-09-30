<?php

namespace Ambta\DoctrineEncryptBundle\Subscribers;

use Ambta\DoctrineEncryptBundle\Configuration\Encrypted;
use Ambta\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use Ambta\DoctrineEncryptBundle\Encryptors\Rijndael256Encryptor;
use Doctrine\Common\Util\ClassUtils;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Event\PostLoadEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\ORM\Event\PrePersistEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\Common\Annotations\Reader;
use Doctrine\Persistence\Proxy;
use \ReflectionClass;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber {
    /**
     * Encryptor interface namespace
     */
    final public const ENCRYPTOR_INTERFACE_NS = EncryptorInterface::class;
    /**
     * Encrypted annotation full name
     */
    final public const ENCRYPTED_ANN_NAME = Encrypted::class;
    /**
     * Encryptor
     *
     * @var EncryptorInterface
     */
    private $encryptor;
    /**
     * Encryptor
     *
     * @var EncryptorInterface
     */
    private $oldEncryptor;
    /**
     * Registry to avoid multi decode operations for one entity
     *
     * @var array
     */
    private $decodedRegistry = [];

    /**
     * Used for restoring the encryptor after changing it
     *
     * @var string
     */
    private $restoreEncryptor;

    /**
     * Count amount of decrypted values in this service
     *
     * @var integer
     */
    public $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     *
     * @var integer
     */
    public $encryptCounter = 0;

    /**
     * Initialization of subscriber
     *
     * @param string $encryptorClass  The encryptor class.  This can be empty if a service is being provided.
     * @param string $secretKey The secret key.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     *
     * This allows for the use of dependency injection for the encrypters.
     * @param string $suffix
     */
    public function __construct(
        $encryptorClass,
        private $secretKey,
        private $suffix,
        EncryptorInterface $service = null
    ) {
        if ($service instanceof EncryptorInterface) {
            $this->encryptor = $service;
        } else {
            $this->encryptor = $this->encryptorFactory(
                $encryptorClass,
                $this->secretKey,
                $this->suffix
            );
        }

        $this->oldEncryptor = $this->encryptorFactory(
            Rijndael256Encryptor::class,
            $this->secretKey,
            $this->suffix
        );

        $this->restoreEncryptor = $this->encryptor;
    }

    /**
     * Change the encryptor
     *
     * @param $encryptorClass
     */
    public function setEncryptor($encryptorClass)
    {

        if(!is_null($encryptorClass)) {
            $this->encryptor = $this->encryptorFactory(
                $encryptorClass,
                $this->secretKey,
                $this->suffix
            );

            return;
        }

        $this->encryptor = null;
    }

    /**
     * Get the current encryptor
     */
    public function getEncryptor()
    {
        if(!empty($this->encryptor)) {
            return $this->encryptor::class;
        } else {
            return null;
        }
    }

    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor() {
        $this->encryptor = $this->restoreEncryptor;
    }

    /**
     * Listen a postUpdate lifecycle event.
     * Decrypt entities property's values when post updated.
     *
     * So for example after form submit the preUpdate encrypted the entity
     * We have to decrypt them before showing them again.
     */
    public function postUpdate(LifecycleEventArgs $args) {

        $entity = $args->getEntity();
        $this->processFields($entity, false);

    }

    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entities property's values on preUpdate, so they will be stored encrypted
     */
    public function preUpdate(PreUpdateEventArgs $args)
    {
        $entity = $args->getObject();
        $this->processFields($entity);
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     */
    public function postLoad(PostLoadEventArgs $args)
    {

        //Get entity and process fields
        $entity = $args->getObject();
        $this->processFields($entity, false);

    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     */
    public function prePersist(PrePersistEventArgs $args)
    {

        //Get entity and process fields
        $entity = $args->getObject();
        $this->processFields($entity);

    }

    /**
     * Listen to preflush event
     * Encrypt entities that are inserted into the database
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs)
    {
        $unitOfWork = $preFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $className => $entities) {
            $class = $preFlushEventArgs->getObjectManager()->getClassMetadata(
                $className
            );
            if ($class->isReadOnly) {
                continue;
            }

            foreach ($entities as $entity) {
                if ($entity instanceof Proxy && !$entity->__isInitialized()) {
                    continue;
                }
                $this->processFields($entity);

            }
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities that after inserted into the database
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs)
    {
        $unitOfWork = $postFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach($unitOfWork->getIdentityMap() as $entityMap) {
            foreach($entityMap as $entity) {
                $this->processFields($entity, false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
    {
        return [
            Events::prePersist,
            Events::preUpdate,
            Events::postLoad,
            Events::preFlush,
            Events::postFlush,
        ];
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object $entity doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     *
     * @return object|null
     * @throws \RuntimeException
     *
     */
    public function processFields($entity, $isEncryptOperation = true)
    {
        if(!empty($this->encryptor)) {

            //Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';


            //Get the real class, we don't want to use the proxy classes
            if(strstr($entity::class, "Proxies")) {
                $realClass = ClassUtils::getClass($entity);
            } else {
                $realClass = $entity::class;
            }

            //Get ReflectionClass of our entity
            $properties = $this->getClassProperties($realClass);


            //Foreach property in the reflection class
            foreach ($properties as $refProperty) {
                

                if (count(
                        $refProperty->getAttributes(
                            \Doctrine\ORM\Mapping\Embedded::class
                        )
                    ) > 0
                ) {
                    $this->handleEmbeddedAnnotation(
                        $entity,
                        $refProperty,
                        $isEncryptOperation
                    );
                    continue;
                }

               /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if (count(
                        $refProperty->getAttributes(self::ENCRYPTED_ANN_NAME)
                    ) > 0
                ) {

                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $refProperty->getName());

                    if($encryptorMethod == "decrypt") {
                        if(!is_null($value) and !empty($value)) {
                            if(str_ends_with((string) $value, "<ENC>")) {
                                $this->decryptCounter++;
                                $currentPropValue = $this->encryptor->decrypt(
                                    substr((string)$value, 0, -5)
                                );
                                $pac->setValue(
                                    $entity,
                                    $refProperty->getName(),
                                    $currentPropValue
                                );
                            }else{
                                $currentPropValue
                                    = $this->oldEncryptor->decrypt($value);
                                $pac->setValue(
                                    $entity,
                                    $refProperty->getName(),
                                    $currentPropValue
                                );
                            }


                        }
                    } else {
                        if(!is_null($value) and !empty($value)) {
                            if(!str_ends_with((string) $value, "<ENC>")) {
                                $this->encryptCounter++;
                                $currentPropValue = $this->encryptor->encrypt(
                                    $value
                                );
                                $pac->setValue(
                                    $entity,
                                    $refProperty->getName(),
                                    $currentPropValue
                                );
                            }
                        }
                    }
                }
            }

            return $entity;
        }

        return null;
    }

    private function handleEmbeddedAnnotation(
        $entity,
        $embeddedProperty,
        $isEncryptOperation = true
    ) {
        $reflectionClass = new ReflectionClass($entity);
        $propName = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embeddedEntity = $pac->getValue($entity, $propName);

        if ($embeddedEntity) {
            $this->processFields($embeddedEntity, $isEncryptOperation);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return \ReflectionProperty[]
     */
    private function getClassProperties($className)
    {

        $reflectionClass = new ReflectionClass($className);
        $properties = $reflectionClass->getProperties();
        $propertiesArray = [];

        foreach($properties as $property){
            $propertyName = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }

        if($parentClass = $reflectionClass->getParentClass()){
            $parentPropertiesArray = $this->getClassProperties(
                $parentClass->getName()
            );
            if (count($parentPropertiesArray) > 0) {
                $propertiesArray = array_merge(
                    $parentPropertiesArray,
                    $propertiesArray
                );
            }
        }

        return $propertiesArray;
    }

    /**
     * Encryptor factory. Checks and create needed encryptor
     *
     * @param string $classFullName Encryptor namespace and name
     * @param string $secretKey Secret key for encryptor
     *
     * @return EncryptorInterface
     * @throws \RuntimeException
     */
    private function encryptorFactory($classFullName, $secretKey, $suffix)
    {
        $refClass = new \ReflectionClass($classFullName);
        if ($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
            return new $classFullName($secretKey, $suffix);
        } else {
            throw new \RuntimeException(
                'Encryptor must implements interface EncryptorInterface'
            );
        }
    }

}