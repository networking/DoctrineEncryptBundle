<?php

namespace Ambta\DoctrineEncryptBundle;

use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Ambta\DoctrineEncryptBundle\DependencyInjection\DoctrineEncryptExtension;
use Ambta\DoctrineEncryptBundle\DependencyInjection\Compiler\RegisterServiceCompilerPass;

class AmbtaDoctrineEncryptBundle extends Bundle {
    
    public function getContainerExtension():?ExtensionInterface
    {
        return new DoctrineEncryptExtension();
    }
}
