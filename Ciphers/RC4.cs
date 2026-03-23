using CryptoCoursework.Interfaces;

namespace CryptoCoursework.Ciphers
{
    public class Rc4Cipher : IStreamCipher
    {
        private byte[] _S = new byte[256];
        private int _i = 0;
        private int _j = 0;
        private bool _initialized = false;

        //KSA
        public void SetKey(byte[] key)
        {
            // Инициализация S-бокса
            for (int i = 0; i < 256; i++)
            { _S[i] = (byte)i; }

            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + _S[i] + key[i % key.Length]) % 256;
                (_S[i], _S[j]) = (_S[j], _S[i]);
            }

            _i = 0;
            _j = 0;
            _initialized = true;
        }

        //PRGA
        public byte[] ProcessBytes(byte[] input, int offset = 0, int length = -1)
        {
            if (!_initialized) throw new InvalidOperationException("Ключ не установлен");

            if (length == -1)
                length = input.Length - offset;

            byte[] output = new byte[length];

            for (int k = 0; k < length; k++)
            {
                _i = (_i + 1) % 256;
                _j = (_j + _S[_i]) % 256;

                (_S[_i], _S[_j]) = (_S[_j], _S[_i]);

                byte t = (byte)((_S[_i] + _S[_j]) % 256);
                output[k] = (byte)(input[offset + k] ^ _S[t]);
            }

            return output;
        }
    }
}