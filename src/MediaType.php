<?php

declare(strict_types=1);

namespace I2crm\WhatsApp;

/**
 * Тип медиа для выбора строки Application Info в HKDF.
 */
final class MediaType
{
    private function __construct()
    {
    }

    public const IMAGE = 'IMAGE';
    public const VIDEO = 'VIDEO';
    public const AUDIO = 'AUDIO';
    public const DOCUMENT = 'DOCUMENT';

    /**
     * @throws \InvalidArgumentException
     */
    public static function hkdfInfo(string $mediaType): string
    {
        return match ($mediaType) {
            self::IMAGE => 'WhatsApp Image Keys',
            self::VIDEO => 'WhatsApp Video Keys',
            self::AUDIO => 'WhatsApp Audio Keys',
            self::DOCUMENT => 'WhatsApp Document Keys',
            default => throw new \InvalidArgumentException('Неизвестный media type: ' . $mediaType),
        };
    }
}

