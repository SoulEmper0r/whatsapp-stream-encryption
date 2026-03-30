<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Stream;

/**
 * Генератор sidecar для стриминга WhatsApp.
 *
 * Правило: подписываем каждый диапазон данных
 * [n*64K, (n+1)*64K+16] ключом macKey (HMAC-SHA256),
 * берём первые 10 байт и склеиваем.
 *
 * Важно: генерация идёт «на лету» — без дополнительных чтений из исходного потока.
 */
final class SidecarGenerator
{
    private const CHUNK = 65536; // 64K
    private const OVERLAP = 16;
    private const MAC_TRUNC = 10;

    private string $buffer = '';
    private string $sidecar = '';

    public function __construct(
        private readonly string $macKey,
        string $prefix = ''
    )
    {
        if (\strlen($this->macKey) !== 32) {
            throw new \InvalidArgumentException('macKey должен быть 32 байта.');
        }

        // Для совместимости с WhatsApp первый диапазон начинается с iv + mediaData.
        $this->buffer = $prefix;
    }

    /**
     * Принимает очередную порцию mediaData.
     */
    public function push(string $chunk): void
    {
        if ($chunk === '') {
            return;
        }

        $this->buffer .= $chunk;
        $need = self::CHUNK + self::OVERLAP;

        while (\strlen($this->buffer) >= $need) {
            $piece = \substr($this->buffer, 0, $need);
            $h = \hash_hmac('sha256', $piece, $this->macKey, true);
            $this->sidecar .= \substr($h, 0, self::MAC_TRUNC);

            // сдвигаем на 64K, оставляя 16 байт перекрытия
            $this->buffer = \substr($this->buffer, self::CHUNK);
        }
    }

    /**
     * Завершение: подписываем «хвост» (если он есть).
     */
    public function finalize(string $tail = ''): void
    {
        if ($tail !== '') {
            $this->push($tail);
        }

        if ($this->buffer === '') {
            return;
        }

        $h = \hash_hmac('sha256', $this->buffer, $this->macKey, true);
        $this->sidecar .= \substr($h, 0, self::MAC_TRUNC);
        $this->buffer = '';
    }

    public function sidecar(): string
    {
        return $this->sidecar;
    }
}

