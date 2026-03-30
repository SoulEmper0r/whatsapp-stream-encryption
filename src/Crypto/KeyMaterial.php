<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Crypto;

/**
 * Производные материалы ключа WhatsApp media.
 */
final class KeyMaterial
{
    public function __construct(
        public readonly string $iv,
        public readonly string $cipherKey,
        public readonly string $macKey,
    ) {
        if (\strlen($this->iv) !== 16) {
            throw new \InvalidArgumentException('IV должен быть 16 байт.');
        }
        if (\strlen($this->cipherKey) !== 32) {
            throw new \InvalidArgumentException('cipherKey должен быть 32 байта.');
        }
        if (\strlen($this->macKey) !== 32) {
            throw new \InvalidArgumentException('macKey должен быть 32 байта.');
        }
    }
}

