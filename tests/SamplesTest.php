<?php

declare(strict_types=1);

namespace I2crm\WhatsApp\Tests;

use GuzzleHttp\Psr7\Utils;
use I2crm\WhatsApp\Crypto\KeyDeriver;
use I2crm\WhatsApp\MediaType;
use I2crm\WhatsApp\Stream\DecryptingStream;
use I2crm\WhatsApp\Stream\EncryptingStream;
use I2crm\WhatsApp\Stream\SidecarGenerator;
use PHPUnit\Framework\TestCase;

final class SamplesTest extends TestCase
{
    public function testDecryptSamples(): void
    {
        foreach ([MediaType::IMAGE, MediaType::AUDIO, MediaType::VIDEO] as $type) {
            $key = $this->readSample("{$type}.key");
            $keys = KeyDeriver::derive($key, $type);

            $encrypted = $this->readSample("{$type}.encrypted");
            $encryptedStream = Utils::streamFor($encrypted);

            $dec = new DecryptingStream($encryptedStream, $keys);
            $plain = $dec->getContents();

            $original = $this->readSample("{$type}.original");
            self::assertSame($original, $plain, "Дешифрование {$type} должно совпадать с *.original");
        }
    }

    public function testEncryptSamples(): void
    {
        foreach ([MediaType::IMAGE, MediaType::AUDIO, MediaType::VIDEO] as $type) {
            $key = $this->readSample("{$type}.key");
            $keys = KeyDeriver::derive($key, $type);

            $original = $this->readSample("{$type}.original");
            $originalStream = Utils::streamFor($original);

            $enc = new EncryptingStream($originalStream, $keys);
            $encrypted = $enc->getContents();

            $expected = $this->readSample("{$type}.encrypted");
            self::assertSame($expected, $encrypted, "Шифрование {$type} должно совпадать с *.encrypted");
        }
    }

    public function testVideoSidecarMatchesSample(): void
    {
        $type = MediaType::VIDEO;
        $key = $this->readSample("{$type}.key");
        $keys = KeyDeriver::derive($key, $type);

        $original = $this->readSample("{$type}.original");
        $originalStream = Utils::streamFor($original);

        $sidecarGen = new SidecarGenerator($keys->macKey, $keys->iv);
        $enc = new EncryptingStream($originalStream, $keys, $sidecarGen);
        $encrypted = $enc->getContents();

        // В encrypted в конце лежит MAC (10 байт).
        self::assertGreaterThan(10, \strlen($encrypted));

        $expectedSidecar = $this->readSample('VIDEO.sidecar');
        self::assertSame($expectedSidecar, $sidecarGen->sidecar(), 'Sidecar для VIDEO должен совпадать с samples/VIDEO.sidecar');

        // Доп. проверка: sidecar можно воспроизвести из iv + mediaData (ciphertext + final mac).
        $fromCipher = $this->generateSidecar($encrypted, $keys->iv, $keys->macKey);
        self::assertSame($expectedSidecar, $fromCipher);
    }

    private function generateSidecar(string $mediaData, string $iv, string $macKey): string
    {
        $g = new SidecarGenerator($macKey, $iv);
        // Подаём порциями, чтобы проверить стриминговый характер.
        $pos = 0;
        $step = 10000;
        while ($pos < \strlen($mediaData)) {
            $g->push(\substr($mediaData, $pos, $step));
            $pos += $step;
        }
        $g->finalize();
        return $g->sidecar();
    }

    private function readSample(string $filename): string
    {
        $path = \dirname(__DIR__) . DIRECTORY_SEPARATOR . 'samples' . DIRECTORY_SEPARATOR . $filename;
        $data = \file_get_contents($path);
        if ($data === false) {
            throw new \RuntimeException('Не удалось прочитать файл сэмпла: ' . $path);
        }
        return $data;
    }
}

