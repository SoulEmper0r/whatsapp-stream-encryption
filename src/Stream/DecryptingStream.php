<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Stream;

use I2crm\WhatsApp\Crypto\KeyMaterial;
use I2crm\WhatsApp\Crypto\Pkcs7;
use Psr\Http\Message\StreamInterface;

/**
 * Декоратор PSR-7 потока, который отдаёт расшифрованные байты по алгоритму WhatsApp.
 *
 * Ожидаемый формат входа: ciphertext + mac(10 байт),
 * где mac = HMAC_SHA256(macKey, iv + ciphertext)[:10]
 */
final class DecryptingStream implements StreamInterface
{
    private const AES = 'aes-256-cbc';
    private const BLOCK = 16;
    private const MAC_TRUNC = 10;

    private string $inBuffer = '';
    private string $macTail = '';
    private string $outBuffer = '';
    private bool $finalized = false;
    private string $ivCurrent;
    private string $plainHold = '';

    /** @var resource|null */
    private $hmacCtx;

    public function __construct(
        private readonly StreamInterface $source,
        private readonly KeyMaterial $keys,
        private readonly int $readChunkSize = 8192,
    ) {
        if ($this->readChunkSize < 1) {
            throw new \InvalidArgumentException('readChunkSize должен быть > 0.');
        }

        $this->ivCurrent = $this->keys->iv;

        $this->hmacCtx = \hash_init('sha256', HASH_HMAC, $this->keys->macKey);
        \hash_update($this->hmacCtx, $this->keys->iv);
    }

    public function __toString(): string
    {
        try {
            if ($this->isSeekable()) {
                $this->rewind();
            }
            return $this->getContents();
        } catch (\Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        $this->source->close();
    }

    public function detach()
    {
        return $this->source->detach();
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        throw new \RuntimeException('DecryptingStream не поддерживает tell().');
    }

    public function eof(): bool
    {
        return $this->finalized && $this->outBuffer === '';
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        throw new \RuntimeException('DecryptingStream не поддерживает seek().');
    }

    public function rewind(): void
    {
        throw new \RuntimeException('DecryptingStream не поддерживает rewind().');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new \RuntimeException('DecryptingStream доступен только для чтения.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read($length): string
    {
        if ($length <= 0) {
            return '';
        }

        while (\strlen($this->outBuffer) < $length && !$this->finalized) {
            $this->pump();
        }

        $out = \substr($this->outBuffer, 0, $length);
        $this->outBuffer = \substr($this->outBuffer, \strlen($out));
        return $out;
    }

    public function getContents(): string
    {
        $result = '';
        while (!$this->eof()) {
            $result .= $this->read(8192);
        }
        return $result;
    }

    public function getMetadata($key = null)
    {
        return $this->source->getMetadata($key);
    }

    private function pump(): void
    {
        $chunk = $this->source->read($this->readChunkSize);
        if ($chunk !== '') {
            $this->appendIncoming($chunk);
        }

        if (!$this->source->eof()) {
            $this->decryptAvailableBlocks();
            return;
        }

        $this->finalizeDecryption();
    }

    private function appendIncoming(string $data): void
    {
        // Хвост MAC (10 байт) должен оставаться отдельно.
        $combined = $this->macTail . $data;
        if (\strlen($combined) <= self::MAC_TRUNC) {
            $this->macTail = $combined;
            return;
        }

        $cut = \strlen($combined) - self::MAC_TRUNC;
        $this->inBuffer .= \substr($combined, 0, $cut);
        $this->macTail = \substr($combined, $cut);
    }

    private function decryptAvailableBlocks(): void
    {
        $available = \strlen($this->inBuffer);
        $fullBlocks = intdiv($available, self::BLOCK);

        // Держим хотя бы 1 блок ciphertext до конца, чтобы корректно снять padding после EOF.
        if ($fullBlocks <= 1) {
            return;
        }

        $toDecLen = ($fullBlocks - 1) * self::BLOCK;
        $cipher = \substr($this->inBuffer, 0, $toDecLen);
        $this->inBuffer = \substr($this->inBuffer, $toDecLen);

        $plain = $this->aesCbcDecryptNoPadding($cipher);

        // Для padding нужно удерживать последний блок plaintext.
        $this->pushPlaintextKeepingTail($plain, false);
    }

    private function finalizeDecryption(): void
    {
        if ($this->finalized) {
            return;
        }

        if (\strlen($this->macTail) !== self::MAC_TRUNC) {
            throw new \RuntimeException('Недостаточно данных: отсутствует MAC (10 байт).');
        }
        if ((\strlen($this->inBuffer) % self::BLOCK) !== 0) {
            throw new \RuntimeException('Некорректная длина ciphertext: не кратна 16.');
        }

        // Дешифруем оставшийся ciphertext (включая последний блок).
        if ($this->inBuffer !== '') {
            $plain = $this->aesCbcDecryptNoPadding($this->inBuffer);
            $this->inBuffer = '';
            $this->pushPlaintextKeepingTail($plain, true);
        } else {
            // Если plaintext не пришёл совсем — padding всё равно должен существовать (минимум 1 блок).
            throw new \RuntimeException('Недостаточно данных: ciphertext пуст.');
        }

        // Проверка MAC.
        $macFull = \hash_final($this->hmacCtx, true);
        $this->hmacCtx = null;
        $expected = \substr($macFull, 0, self::MAC_TRUNC);
        if (!\hash_equals($expected, $this->macTail)) {
            throw new \RuntimeException('Некорректный MAC: данные повреждены или ключ неверный.');
        }

        $this->macTail = '';
        $this->finalized = true;
    }

    private function pushPlaintextKeepingTail(string $plain, bool $isFinal): void
    {
        if ($plain === '') {
            return;
        }

        $plain = $this->plainHold . $plain;
        $this->plainHold = '';

        if (!$isFinal) {
            if (\strlen($plain) <= self::BLOCK) {
                $this->plainHold = $plain;
                return;
            }
            $emitLen = \strlen($plain) - self::BLOCK;
            $this->outBuffer .= \substr($plain, 0, $emitLen);
            $this->plainHold = \substr($plain, $emitLen);
            return;
        }

        // Финал: распаковываем padding с удержанного последнего блока.
        $unpadded = Pkcs7::unpad($plain, self::BLOCK);
        $this->outBuffer .= $unpadded;
        $this->plainHold = '';
    }

    private function aesCbcDecryptNoPadding(string $ciphertext): string
    {
        if (($len = \strlen($ciphertext)) === 0) {
            return '';
        }
        if (($len % self::BLOCK) !== 0) {
            throw new \LogicException('Внутренняя ошибка: ciphertext не кратен размеру блока.');
        }

        \hash_update($this->hmacCtx, $ciphertext);

        $plain = \openssl_decrypt(
            $ciphertext,
            self::AES,
            $this->keys->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->ivCurrent
        );

        if ($plain === false) {
            throw new \RuntimeException('openssl_decrypt вернул false.');
        }

        // В CBC IV для следующего блока — последний блок ciphertext.
        $this->ivCurrent = \substr($ciphertext, -self::BLOCK);

        return $plain;
    }
}

