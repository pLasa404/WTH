using CryptoCoursework.Interfaces;

namespace CryptoCoursework.Ciphers
{
    public class TripleDesCipher : IBlockCipher
    {
        private readonly DesCipher _des1 = new DesCipher();
        private readonly DesCipher _des2 = new DesCipher();
        private readonly DesCipher _des3 = new DesCipher();

        public int BlockSize => 64;
        public int KeySize => 192;

        public void SetKey(byte[] key)
        {
            if (key.Length == 16)
            {
                _des1.SetKey(key[..8]);
                _des2.SetKey(key[8..]);
                _des3.SetKey(key[..8]);
            }
            else if (key.Length == 24)
            {
                _des1.SetKey(key[..8]);
                _des2.SetKey(key[8..16]);
                _des3.SetKey(key[16..]);
            }
            else
                throw new ArgumentException("Invalid 3DES key length");
        }

        public byte[] EncryptBlock(byte[] input, int offset = 0)
        {
            var step1 = _des1.EncryptBlock(input, offset);
            var step2 = _des2.DecryptBlock(step1);
            return _des3.EncryptBlock(step2);
        }

        public byte[] DecryptBlock(byte[] input, int offset = 0)
        {
            var step1 = _des3.DecryptBlock(input, offset);
            var step2 = _des2.EncryptBlock(step1);
            return _des1.DecryptBlock(step2);
        }
    }
}