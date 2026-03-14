using System;
using System.Collections.Generic;
using System.Text;

namespace CryptoCoursework.Interfaces
{
    public interface IStreamCipher
    {
        void SetKey(byte[] key);
        byte[] ProcessBytes(byte[] input, int offset = 0, int length = -1);
    }
}