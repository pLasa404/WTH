using CryptoCoursework.Interfaces;

namespace CryptoCoursework.Ciphers
{
    public class DealCipher : IBlockCipher
    {
        private readonly DesCipher _des = new DesCipher();
        private byte[][] _roundKeys;
        private int _rounds;

        public int BlockSize => 128;
        public int KeySize => 256;

        public void SetKey(byte[] key)
        {
            _rounds = key.Length <= 24 ? 6 : 8;
            _roundKeys = GenerateRoundKeys(key, _rounds);
        }

        private byte[][] GenerateRoundKeys(byte[] key, int rounds)
        {
            byte[][] keys = new byte[rounds][];
            for (int i = 0; i < rounds; i++)
            {
                keys[i] = new byte[8];
                Array.Copy(key, (i * 8) % key.Length, keys[i], 0, 8);
            }
            return keys;
        }

        public byte[] EncryptBlock(byte[] input, int offset = 0)
        {
            byte[] L = new byte[8], R = new byte[8];
            Array.Copy(input, offset, L, 0, 8);
            Array.Copy(input, offset + 8, R, 0, 8);

            for (int i = 0; i < _rounds; i++)
            {
                _des.SetKey(_roundKeys[i]);
                byte[] fOut = _des.EncryptBlock(R);
                byte[] newR = XorBytes(L, fOut);
                L = R;
                R = newR;
            }

            byte[] result = new byte[16];
            Array.Copy(L, 0, result, 0, 8);
            Array.Copy(R, 0, result, 8, 8);
            return result;
        }

        public byte[] DecryptBlock(byte[] input, int offset = 0)
        {
            byte[] L = new byte[8], R = new byte[8];
            Array.Copy(input, offset, L, 0, 8);
            Array.Copy(input, offset + 8, R, 0, 8);

            for (int i = _rounds - 1; i >= 0; i--)
            {
                _des.SetKey(_roundKeys[i]);
                byte[] fOut = _des.EncryptBlock(L);
                byte[] newL = XorBytes(R, fOut);
                R = L;
                L = newL;
            }

            byte[] result = new byte[16];
            Array.Copy(L, 0, result, 0, 8);
            Array.Copy(R, 0, result, 8, 8);
            return result;
        }

        private byte[] XorBytes(byte[] a, byte[] b)
        {
            byte[] result = new byte[8];
            for (int i = 0; i < 8; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }
    }
}