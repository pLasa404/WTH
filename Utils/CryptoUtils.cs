 using System;

namespace CryptoCoursework.Utils
{
    public static class CryptoUtils
    {
        public static byte[] XorBytes(byte[] a, byte[] b)
        {
            byte[] result = new byte[Math.Min(a.Length, b.Length)];
            for (int i = 0; i < result.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);
            return result;
        }

        public static uint RotateLeft(uint value, int shift)
        {
            shift %= 32;
            return (value << shift) | (value >> (32 - shift));
        }

        public static uint RotateRight(uint value, int shift)
        {
            shift %= 32;
            return (value >> shift) | (value << (32 - shift));
        }

        public static uint BytesToUint(byte[] data, int offset)
        {
            return (uint)(data[offset] | (data[offset + 1] << 8) |
                         (data[offset + 2] << 16) | (data[offset + 3] << 24));
        }

        public static void UintToBytes(uint value, byte[] data, int offset)
        {
            data[offset] = (byte)value;
            data[offset + 1] = (byte)(value >> 8);
            data[offset + 2] = (byte)(value >> 16);
            data[offset + 3] = (byte)(value >> 24);
        }

        public static ulong BytesToUlong(byte[] data, int offset)
        {
            uint low = BytesToUint(data, offset);
            uint high = BytesToUint(data, offset + 4);
            return ((ulong)high << 32) | low;
        }

        public static void UlongToBytes(ulong value, byte[] data, int offset)
        {
            UintToBytes((uint)value, data, offset);
            UintToBytes((uint)(value >> 32), data, offset + 4);
        }

        public static byte[] GenerateRandomBytes(int length)
        {
            byte[] random = new byte[length];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(random);
            return random;
        }
    }
}