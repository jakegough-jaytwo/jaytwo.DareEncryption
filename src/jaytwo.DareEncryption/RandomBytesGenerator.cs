using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class RandomBytesGenerator : IRandomBytesGenerator
    {
        public RandomBytesGenerator(int nonceLength)
        {
            NonceLength = nonceLength;
        }

        public int NonceLength { get; }

        public byte[] GetRandomBytes() => GetRandomBytes(NonceLength);

        private static byte[] GetRandomBytes(int length)
        {
            var result = new byte[length];
            RandomNumberGenerator.Fill(result);
            return result;
        }
    }
}
