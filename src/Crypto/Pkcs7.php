<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Crypto;

/**
 * Заполнение PKCS#7 для блока AES размером 16.
 */
final class Pkcs7
{
    private function __construct()
    {
    }

    public static function pad(string $data, int $blockSize = 16): string
    {
        if ($blockSize <= 0 || $blockSize > 255) {
            throw new \InvalidArgumentException('Некорректный размер блока.');
        }
        $padLen = $blockSize - (\strlen($data) % $blockSize);
        if ($padLen === 0) {
            $padLen = $blockSize;
        }
        return $data . \str_repeat(\chr($padLen), $padLen);
    }

    /**
     * @throws \RuntimeException
     */
    public static function unpad(string $data, int $blockSize = 16): string
    {
        $len = \strlen($data);
        if ($len === 0 || ($len % $blockSize) !== 0) {
            throw new \RuntimeException('Некорректная длина данных для PKCS#7.');
        }
        $padLen = \ord($data[$len - 1]);
        if ($padLen <= 0 || $padLen > $blockSize) {
            throw new \RuntimeException('Некорректный padding PKCS#7.');
        }
        for ($i = 1; $i <= $padLen; $i++) {
            if (\ord($data[$len - $i]) !== $padLen) {
                throw new \RuntimeException('Некорректный padding PKCS#7.');
            }
        }
        return \substr($data, 0, $len - $padLen);
    }
}

