<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Crypto;

/**
 * HKDF по RFC 5869 (HMAC-SHA256).
 *
 * Используем salt = пустая строка, как в описании задания.
 */
final class Hkdf
{
    private function __construct()
    {
    }

    public static function sha256(string $ikm, int $length, string $info = ''): string
    {
        if ($length < 0) {
            throw new \InvalidArgumentException('Длина HKDF не может быть отрицательной.');
        }
        if ($length === 0) {
            return '';
        }

        // PHP >= 7.1
        if (\function_exists('hash_hkdf')) {
            /** @var string $okm */
            $okm = \hash_hkdf('sha256', $ikm, $length, $info, '');
            // hash_hkdf возвращает RAW-строку, если последний аргумент salt строка (даже пустая).
            return $okm;
        }

        // Fallback на ручную реализацию RFC 5869.
        $hashLength = 32;
        $iterationCount = (int)\ceil($length / $hashLength);
        if ($iterationCount > 255) {
            throw new \InvalidArgumentException('Слишком большая длина HKDF (n > 255).');
        }

        $salt = '';
        $prk = \hash_hmac('sha256', $ikm, $salt, true);

        $previousBlock = '';
        $okm = '';
        for ($blockIndex = 1; $blockIndex <= $iterationCount; $blockIndex++) {
            $previousBlock = \hash_hmac('sha256', $previousBlock . $info . \chr($blockIndex), $prk, true);
            $okm .= $previousBlock;
        }

        return \substr($okm, 0, $length);
    }
}

