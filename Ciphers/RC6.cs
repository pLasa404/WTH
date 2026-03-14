using CryptoCoursework.Interfaces;
using CryptoCoursework.Utils;

namespace CryptoCoursework.Ciphers
{
    public class Rc6Cipher : IBlockCipher
    {
        private const int ROUNDS = 20;
        private uint[] _S = new uint[44];

        public int BlockSize => 128;
        public int KeySize => 256;

        public void SetKey(byte[] key)
        {
            KeyExpansion(key);
        }

        private void KeyExpansion(byte[] key)
        {
            int c = (key.Length + 3) / 4;
            uint[] L = new uint[c];

            for (int y = 0; y < key.Length; y++)
                L[y / 4] |= ((uint)key[y]) << (8 * (y % 4));

            uint P = 0xB7E15163;
            uint Q = 0x9E3779B9;

            _S[0] = P;
            for (int x = 1; x < _S.Length; x++)
                _S[x] = _S[x - 1] + Q;

            int i = 0, j = 0;
            uint A = 0, B = 0;

            for (int k = 0; k < 3 * Math.Max(_S.Length, c); k++)
            {
                A = _S[i] = CryptoUtils.RotateLeft(_S[i] + A + B, 3);
                B = L[j] = CryptoUtils.RotateLeft(L[j] + A + B, (int)(A + B));
                i = (i + 1) % _S.Length;
                j = (j + 1) % c;
            }
        }

        public byte[] EncryptBlock(byte[] input, int offset = 0)
        {
            uint A = CryptoUtils.BytesToUint(input, offset);
            uint B = CryptoUtils.BytesToUint(input, offset + 4);
            uint C = CryptoUtils.BytesToUint(input, offset + 8);
            uint D = CryptoUtils.BytesToUint(input, offset + 12);

            B += _S[0];
            D += _S[1];

            for (int i = 0; i < ROUNDS; i++)
            {
                uint t = CryptoUtils.RotateLeft(B * (2 * B + 1), 5);
                uint u = CryptoUtils.RotateLeft(D * (2 * D + 1), 5);

                A = CryptoUtils.RotateLeft(A ^ t, (int)u) + _S[2 * i + 2];
                C = CryptoUtils.RotateLeft(C ^ u, (int)t) + _S[2 * i + 3];

                (A, B, C, D) = (B, C, D, A);
            }

            A += _S[40];
            C += _S[41];

            byte[] output = new byte[16];
            CryptoUtils.UintToBytes(A, output, 0);
            CryptoUtils.UintToBytes(B, output, 4);
            CryptoUtils.UintToBytes(C, output, 8);
            CryptoUtils.UintToBytes(D, output, 12);

            return output;
        }

        public byte[] DecryptBlock(byte[] input, int offset = 0)
        {
            uint A = CryptoUtils.BytesToUint(input, offset);
            uint B = CryptoUtils.BytesToUint(input, offset + 4);
            uint C = CryptoUtils.BytesToUint(input, offset + 8);
            uint D = CryptoUtils.BytesToUint(input, offset + 12);

            C -= _S[41];
            A -= _S[40];

            for (int i = ROUNDS - 1; i >= 0; i--)
            {
                (A, B, C, D) = (D, A, B, C);

                uint t = CryptoUtils.RotateLeft(B * (2 * B + 1), 5);
                uint u = CryptoUtils.RotateLeft(D * (2 * D + 1), 5);

                C = CryptoUtils.RotateLeft(C - _S[2 * i + 3], (int)t) ^ u;
                A = CryptoUtils.RotateLeft(A - _S[2 * i + 2], (int)u) ^ t;
            }

            D -= _S[1];
            B -= _S[0];

            byte[] output = new byte[16];
            CryptoUtils.UintToBytes(A, output, 0);
            CryptoUtils.UintToBytes(B, output, 4);
            CryptoUtils.UintToBytes(C, output, 8);
            CryptoUtils.UintToBytes(D, output, 12);

            return output;
        }
    }
}