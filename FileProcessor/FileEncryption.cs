using CryptoCoursework.Ciphers;
using CryptoCoursework.Interfaces;
using CryptoCoursework.Modes;
using CryptoCoursework.Padding;
using System.Collections.Generic;
using System.IO;

namespace CryptoCoursework.FileProcessor
{
    public class FileEncryption
    {
        private readonly IBlockCipher? _cipher;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        public Rc4Cipher? Rc4 { get; }

        // Конструктор для блочных шифров
        public FileEncryption(IBlockCipher cipher, CipherMode mode, PaddingMode padding)
        {
            _cipher = cipher;
            _mode = mode;
            _padding = padding;
        }

        // Конструктор для RC4 (поточный шифр)
        public FileEncryption(Rc4Cipher rc4)
        {
            Rc4 = rc4;
        }

        // ШИФРОВАНИЕ
        public async Task EncryptFileAsync(string input, string output, byte[] key, byte[] iv)
        {
            if (_cipher == null) throw new InvalidOperationException("Block cipher not initialized.");

            _cipher.SetKey(key);
            var blockSize = _cipher.BlockSize / 8;

            using var ins = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            using var outs = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

            // Записываем IV в начало файла (кроме ECB)
            if (_mode != CipherMode.ECB)
            {
                await outs.WriteAsync(iv, 0, iv.Length);
            }

            var allData = new List<byte>();
            var buffer = new byte[4096];
            int read;
            while ((read = await ins.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                for (int i = 0; i < read; i++)
                    allData.Add(buffer[i]);
            }

            var padded = PaddingScheme.Apply(allData.ToArray(), blockSize, _padding);

            switch (_mode)
            {
                case CipherMode.ECB:
                    await Encrypt_ECB(outs, padded, blockSize);
                    break;
                case CipherMode.CBC:
                    await Encrypt_CBC(outs, padded, blockSize, iv);
                    break;
                case CipherMode.PCBC:
                    await Encrypt_PCBC(outs, padded, blockSize, iv);
                    break;
                case CipherMode.CFB:
                    await Encrypt_CFB(outs, padded, blockSize, iv);
                    break;
                case CipherMode.OFB:
                    await Encrypt_OFB(outs, padded, blockSize, iv);
                    break;
                case CipherMode.CTR:
                    await Encrypt_CTR(outs, padded, blockSize, iv);
                    break;
                default:
                    throw new NotSupportedException($"Режим {_mode} не поддерживается");
            }
        }

        // ДЕШИФРОВАНИЕ
        public async Task DecryptFileAsync(string input, string output, byte[] key, byte[]? iv = null)
        {
            if (_cipher == null) throw new InvalidOperationException("Block cipher not initialized.");

            _cipher.SetKey(key);
            var blockSize = _cipher.BlockSize / 8;

            using var ins = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            using var outs = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

            // Читаем IV из файла если не передан (кроме ECB)
            if (_mode != CipherMode.ECB)
            {
                if (iv == null)
                {
                    iv = new byte[blockSize];
                    await ins.ReadAsync(iv, 0, iv.Length);
                }
            }
            else
            {
                iv = new byte[blockSize]; // Для ECB IV создаём пустой
            }

            // Читаем зашифрованные данные
            var encryptedData = new List<byte>();
            var buffer = new byte[4096];
            int read;
            while ((read = await ins.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                for (int i = 0; i < read; i++)
                    encryptedData.Add(buffer[i]);
            }

            // Дешифруем в зависимости от режима
            var decryptedPadded = new List<byte>();
            switch (_mode)
            {
                case CipherMode.ECB:
                    decryptedPadded = Decrypt_ECB(encryptedData, blockSize);
                    break;
                case CipherMode.CBC:
                    decryptedPadded = Decrypt_CBC(encryptedData, blockSize, iv);
                    break;
                case CipherMode.PCBC:
                    decryptedPadded = Decrypt_PCBC(encryptedData, blockSize, iv);
                    break;
                case CipherMode.CFB:
                    decryptedPadded = Decrypt_CFB(encryptedData, blockSize, iv);
                    break;
                case CipherMode.OFB:
                    decryptedPadded = Decrypt_OFB(encryptedData, blockSize, iv);
                    break;
                case CipherMode.CTR:
                    decryptedPadded = Decrypt_CTR(encryptedData, blockSize, iv);
                    break;
                default:
                    throw new NotSupportedException($"Режим {_mode} не поддерживается");
            }

            // Убираем padding
            var finalData = PaddingScheme.Remove(decryptedPadded.ToArray(), _padding);
            await outs.WriteAsync(finalData, 0, finalData.Length);
        }

        // ECB
        private async Task Encrypt_ECB(FileStream outs, byte[] data, int blockSize)
        {
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                var encrypted = _cipher!.EncryptBlock(block);
                await outs.WriteAsync(encrypted, 0, encrypted.Length);
            }
        }

        private List<byte> Decrypt_ECB(List<byte> encryptedData, int blockSize)
        {
            var result = new List<byte>();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                var block = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    block[j] = encryptedData[i + j];
                var decrypted = _cipher!.DecryptBlock(block);
                result.AddRange(decrypted);
            }
            return result;
        }

        // CBC
        private async Task Encrypt_CBC(FileStream outs, byte[] data, int blockSize, byte[] iv)
        {
            var prev = (byte[])iv.Clone();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                var xored = XorBytes(block, prev);
                var encrypted = _cipher!.EncryptBlock(xored);
                await outs.WriteAsync(encrypted, 0, encrypted.Length);
                prev = encrypted;
            }
        }

        private List<byte> Decrypt_CBC(List<byte> encryptedData, int blockSize, byte[] iv)
        {
            var result = new List<byte>();
            var prevCipher = (byte[])iv.Clone();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                var cipherBlock = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    cipherBlock[j] = encryptedData[i + j];
                var decrypted = _cipher!.DecryptBlock(cipherBlock);
                var plain = XorBytes(decrypted, prevCipher);
                result.AddRange(plain);
                prevCipher = cipherBlock;
            }
            return result;
        }

        // PCBC
        private async Task Encrypt_PCBC(FileStream outs, byte[] data, int blockSize, byte[] iv)
        {
            var prevCipher = (byte[])iv.Clone();
            var prevPlain = (byte[])iv.Clone();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, blockSize);
                var toXor = XorBytes(XorBytes(block, prevPlain), prevCipher);
                var encrypted = _cipher!.EncryptBlock(toXor);
                await outs.WriteAsync(encrypted, 0, encrypted.Length);
                prevCipher = encrypted;
                prevPlain = block;
            }
        }

        private List<byte> Decrypt_PCBC(List<byte> encryptedData, int blockSize, byte[] iv)
        {
            var result = new List<byte>();
            var prevCipher = (byte[])iv.Clone();
            var prevPlain = (byte[])iv.Clone();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                var cipherBlock = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    cipherBlock[j] = encryptedData[i + j];
                var decrypted = _cipher!.DecryptBlock(cipherBlock);
                var plain = XorBytes(XorBytes(decrypted, prevCipher), prevPlain);
                result.AddRange(plain);
                prevCipher = cipherBlock;
                prevPlain = plain;
            }
            return result;
        }

        // CFB
        private async Task Encrypt_CFB(FileStream outs, byte[] data, int blockSize, byte[] iv)
        {
            var shiftRegister = (byte[])iv.Clone();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                var encryptedReg = _cipher!.EncryptBlock(shiftRegister);
                var cipherBlock = XorBytes(block, encryptedReg);
                await outs.WriteAsync(cipherBlock, 0, cipherBlock.Length);
                shiftRegister = cipherBlock;
            }
        }

        private List<byte> Decrypt_CFB(List<byte> encryptedData, int blockSize, byte[] iv)
        {
            var result = new List<byte>();
            var shiftRegister = (byte[])iv.Clone();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                var cipherBlock = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    cipherBlock[j] = encryptedData[i + j];
                var encryptedReg = _cipher!.EncryptBlock(shiftRegister);
                var plain = XorBytes(cipherBlock, encryptedReg);
                result.AddRange(plain);
                shiftRegister = cipherBlock;
            }
            return result;
        }

        // OFB
        private async Task Encrypt_OFB(FileStream outs, byte[] data, int blockSize, byte[] iv)
        {
            var o = (byte[])iv.Clone();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                o = _cipher!.EncryptBlock(o);
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                var cipherBlock = XorBytes(block, o);
                await outs.WriteAsync(cipherBlock, 0, cipherBlock.Length);
            }
        }

        private List<byte> Decrypt_OFB(List<byte> encryptedData, int blockSize, byte[] iv)
        {
            var result = new List<byte>();
            var o = (byte[])iv.Clone();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                o = _cipher!.EncryptBlock(o);
                var cipherBlock = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    cipherBlock[j] = encryptedData[i + j];
                var plain = XorBytes(cipherBlock, o);
                result.AddRange(plain);
            }
            return result;
        }

        // CTR 
        private async Task Encrypt_CTR(FileStream outs, byte[] data, int blockSize, byte[] iv)
        {
            var counter = (byte[])iv.Clone();
            for (int i = 0; i < data.Length; i += blockSize)
            {
                var block = new byte[blockSize];
                Array.Copy(data, i, block, 0, Math.Min(blockSize, data.Length - i));
                var keystream = _cipher!.EncryptBlock(counter);
                var cipherBlock = XorBytes(block, keystream);
                await outs.WriteAsync(cipherBlock, 0, cipherBlock.Length);
                IncrementCounter(counter);
            }
        }

        private List<byte> Decrypt_CTR(List<byte> encryptedData, int blockSize, byte[] iv)
        {
            var result = new List<byte>();
            var counter = (byte[])iv.Clone();
            for (int i = 0; i < encryptedData.Count; i += blockSize)
            {
                if (i + blockSize > encryptedData.Count) break;
                var keystream = _cipher!.EncryptBlock(counter);
                var cipherBlock = new byte[blockSize];
                for (int j = 0; j < blockSize; j++)
                    cipherBlock[j] = encryptedData[i + j];
                var plain = XorBytes(cipherBlock, keystream);
                result.AddRange(plain);
                IncrementCounter(counter);
            }
            return result;
        }

        // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ 
        private void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                counter[i]++;
                if (counter[i] != 0) break;
            }
        }

        private byte[] XorBytes(byte[] a, byte[] b)
        {
            var result = new byte[Math.Min(a.Length, b.Length)];
            for (int i = 0; i < result.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }

        // RC4
        public async Task EncryptFileAsync(string input, string output, byte[] key)
        {
            if (Rc4 == null) throw new InvalidOperationException("RC4 cipher not initialized.");
            Rc4.SetKey(key);

            using var ins = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            using var outs = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

            var buffer = new byte[4096];
            int read;
            while ((read = await ins.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                var encrypted = Rc4.ProcessBytes(buffer, 0, read);
                await outs.WriteAsync(encrypted, 0, read);
            }
        }

        public async Task DecryptFileAsync(string input, string output, byte[] key)
        {
            if (Rc4 == null) throw new InvalidOperationException("RC4 cipher not initialized.");
            Rc4.SetKey(key);

            using var ins = new FileStream(input, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, true);
            using var outs = new FileStream(output, FileMode.Create, FileAccess.Write, FileShare.None, 4096, true);

            var buffer = new byte[4096];
            int read;
            while ((read = await ins.ReadAsync(buffer, 0, buffer.Length)) > 0)
            {
                var decrypted = Rc4.ProcessBytes(buffer, 0, read);
                await outs.WriteAsync(decrypted, 0, read);
            }
        }
    }
}