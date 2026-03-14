using System;

namespace CryptoCoursework.Padding
{
    public enum PaddingMode
    {
        Zeros,
        PKCS7,
        ANSIX923,
        ISO10126
    }

    public static class PaddingScheme
    {
        public static byte[] Apply(byte[] data, int blockSize, PaddingMode mode)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            int paddingLen = blockSize - (data.Length % blockSize);
            if (paddingLen == 0) paddingLen = blockSize;

            byte[] padded = new byte[data.Length + paddingLen];
            Array.Copy(data, padded, data.Length);

            switch (mode)
            {
                case PaddingMode.PKCS7:
                    for (int i = 0; i < paddingLen; i++)
                        padded[data.Length + i] = (byte)paddingLen;
                    break;

                case PaddingMode.ANSIX923:
                    padded[padded.Length - 1] = (byte)paddingLen;
                    break;

                case PaddingMode.ISO10126:
                    var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
                    rng.GetBytes(padded, data.Length, paddingLen - 1);
                    padded[padded.Length - 1] = (byte)paddingLen;
                    break;

                case PaddingMode.Zeros:
                default:
                    // Остальные байты уже 0
                    break;
            }

            return padded;
        }

        public static byte[] Remove(byte[] data, PaddingMode mode)
        {
            if (data == null || data.Length == 0) return data;

            try
            {
                int paddingLen = data[data.Length - 1];

                if (paddingLen == 0 || paddingLen > data.Length)
                    return data;

                switch (mode)
                {
                    case PaddingMode.PKCS7:
                        for (int i = 0; i < paddingLen; i++)
                            if (data[data.Length - 1 - i] != paddingLen)
                                return data; // Неверный PKCS#7
                        break;

                    case PaddingMode.ANSIX923:
                    case PaddingMode.ISO10126:
                        break;

                    case PaddingMode.Zeros:
                        // Удаляем все нули с конца
                        int lastNonZero = data.Length - 1;
                        while (lastNonZero >= 0 && data[lastNonZero] == 0)
                            lastNonZero--;
                        byte[] result = new byte[lastNonZero + 1];
                        if (lastNonZero >= 0)
                            Array.Copy(data, result, lastNonZero + 1);
                        return result;
                }

                // Удаление padding'а по длине (для PKCS7, ANSIX923, ISO10126)
                if (data.Length < paddingLen) return data;
                byte[] final = new byte[data.Length - paddingLen];
                Array.Copy(data, final, final.Length);
                return final;
            }
            catch
            {
                // Если что-то пошло не так — возвращаем как есть
                return data;
            }
        }
    }
}