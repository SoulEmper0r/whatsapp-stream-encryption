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
        $hashLen = 32;
        $n = (int)\ceil($length / $hashLen);
        if ($n > 255) {
            throw new \InvalidArgumentException('Слишком большая длина HKDF (n > 255).');
        }

        $salt = '';
        $prk = \hash_hmac('sha256', $ikm, $salt, true);

        $t = '';
        $okm = '';
        for ($i = 1; $i <= $n; $i++) {
            $t = \hash_hmac('sha256', $t . $info . \chr($i), $prk, true);
            $okm .= $t;
        }

        return \substr($okm, 0, $length);
    }
}

