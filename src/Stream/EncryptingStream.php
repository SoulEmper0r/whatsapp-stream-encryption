<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Stream;

use I2crm\WhatsApp\Crypto\KeyMaterial;
use I2crm\WhatsApp\Crypto\Pkcs7;
use Psr\Http\Message\StreamInterface;

/**
 * Декоратор PSR-7 потока, который отдаёт зашифрованные байты по алгоритму WhatsApp.
 *
 * Формат результата: ciphertext + mac(10 байт), где mac = HMAC_SHA256(macKey, iv + ciphertext)[:10]
 */
final class EncryptingStream implements StreamInterface
{
    private const AES = 'aes-256-cbc';
    private const BLOCK = 16;
    private const MAC_TRUNC = 10;

    private string $inBuffer = '';
    private string $outBuffer = '';
    private bool $finalized = false;
    private string $ivCurrent;

    /** @var resource|null */
    private $hmacCtx;

    public function __construct(
        private readonly StreamInterface $source,
        private readonly KeyMaterial $keys,
        private readonly ?SidecarGenerator $sidecar = null,
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
        // Точный размер без полного чтения заранее не вычисляем.
        return null;
    }

    public function tell(): int
    {
        throw new \RuntimeException('EncryptingStream не поддерживает tell().');
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
        throw new \RuntimeException('EncryptingStream не поддерживает seek().');
    }

    public function rewind(): void
    {
        throw new \RuntimeException('EncryptingStream не поддерживает rewind().');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write($string): int
    {
        throw new \RuntimeException('EncryptingStream доступен только для чтения.');
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
            $this->inBuffer .= $chunk;
        }

        $atEof = $this->source->eof();

        if (!$atEof) {
            $this->encryptAvailableBlocks();
            return;
        }

        // EOF: допадим и зашифруем всё, затем добавим mac.
        $this->finalizeEncryption();
    }

    private function encryptAvailableBlocks(): void
    {
        $available = \strlen($this->inBuffer);
        $fullBlocks = intdiv($available, self::BLOCK);

        // Чтобы не «съесть» последний блок до padding, оставляем минимум 1 блок в буфере.
        if ($fullBlocks <= 1) {
            return;
        }

        $toEncLen = ($fullBlocks - 1) * self::BLOCK;
        $plain = \substr($this->inBuffer, 0, $toEncLen);
        $this->inBuffer = \substr($this->inBuffer, $toEncLen);

        $cipher = $this->aesCbcEncryptNoPadding($plain);
        $this->pushCiphertext($cipher);
    }

    private function finalizeEncryption(): void
    {
        if ($this->finalized) {
            return;
        }

        $padded = Pkcs7::pad($this->inBuffer, self::BLOCK);
        $this->inBuffer = '';

        $cipher = $this->aesCbcEncryptNoPadding($padded);
        $this->pushCiphertext($cipher);

        $macFull = \hash_final($this->hmacCtx, true);
        $this->hmacCtx = null;
        $mac = \substr($macFull, 0, self::MAC_TRUNC);
        $this->outBuffer .= $mac;

        if ($this->sidecar) {
            $this->sidecar->finalize($mac);
        }

        $this->finalized = true;
    }

    private function pushCiphertext(string $cipher): void
    {
        if ($cipher === '') {
            return;
        }
        \hash_update($this->hmacCtx, $cipher);
        $this->outBuffer .= $cipher;

        if ($this->sidecar) {
            $this->sidecar->push($cipher);
        }
    }

    private function aesCbcEncryptNoPadding(string $plaintext): string
    {
        if (($len = \strlen($plaintext)) === 0) {
            return '';
        }
        if (($len % self::BLOCK) !== 0) {
            throw new \LogicException('Внутренняя ошибка: plaintext не кратен размеру блока.');
        }

        $cipher = \openssl_encrypt(
            $plaintext,
            self::AES,
            $this->keys->cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->ivCurrent
        );

        if ($cipher === false) {
            throw new \RuntimeException('openssl_encrypt вернул false.');
        }

        // В CBC IV для следующего блока — последний блок ciphertext.
        $this->ivCurrent = \substr($cipher, -self::BLOCK);

        return $cipher;
    }
}

