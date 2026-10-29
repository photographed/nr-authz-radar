<?php
// Without Composer: require this file. With Composer, use the package autoloader instead.
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
    if (str_starts_with($class, 'AuthzRadar\\')) {
        $file = __DIR__ . '/src/' . str_replace('\\', '/', substr($class, \strlen('AuthzRadar\\'))) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});
