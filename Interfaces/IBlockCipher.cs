
namespace CryptoCoursework.Interfaces
{
    public interface IBlockCipher
    {
        int BlockSize { get; }
        int KeySize { get; }
        void SetKey(byte[] key);
        byte[] EncryptBlock(byte[] input, int offset = 0);
        byte[] DecryptBlock(byte[] input, int offset = 0);
    }
}