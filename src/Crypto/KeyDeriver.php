<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Crypto;

use I2crm\WhatsApp\MediaType;

/**
 * Производит iv/cipherKey/macKey из mediaKey по схеме WhatsApp.
 */
final class KeyDeriver
{
    private function __construct()
    {
    }

    /**
     * @param string $mediaKey 32 байта (raw).
     * @param string $mediaType См. константы {@see MediaType}.
     */
    public static function derive(string $mediaKey, string $mediaType): KeyMaterial
    {
        if (\strlen($mediaKey) !== 32) {
            throw new \InvalidArgumentException('mediaKey должен быть 32 байта.');
        }

        $info = MediaType::hkdfInfo($mediaType);
        $expanded = Hkdf::sha256($mediaKey, 112, $info);

        $iv = \substr($expanded, 0, 16);
        $cipherKey = \substr($expanded, 16, 32);
        $macKey = \substr($expanded, 48, 32);

        return new KeyMaterial($iv, $cipherKey, $macKey);
    }
}

