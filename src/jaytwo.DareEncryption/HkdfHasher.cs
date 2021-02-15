using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class HkdfHasher
    {
        public static byte[] GenerateDoubheHashedKey(byte[] secret, byte[] salt, byte[] nonce)
        {
            var firstPass = ComputeHkdfHash(secret, salt);
            var secondPass = ComputeHkdfHash(firstPass, nonce);
            return secondPass;
        }

        // see also: https://github.com/golang/crypto/blob/master/hkdf/hkdf.go#L90-L93
        public static byte[] ComputeHkdfHash(byte[] secret, byte[] salt, byte[] info = null)
        {
            var pseudoRandomKey = Extract(secret, salt);
            var result = Expand(pseudoRandomKey, info, 32);
            return result;
        }

        private static byte[] Extract(byte[] ikv, byte[] salt)
        {
            return Hash(salt, ikv);
        }

        // https://gist.github.com/charlesportwoodii/09ffd6868c2a6e55826c4d5ebb509651
        private static byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            var resultBlock = new byte[0];
            var result = new byte[outputLength];
            var bytesRemaining = outputLength;

            info = info ?? new byte[] { };

            for (int i = 1; bytesRemaining > 0; i++)
            {
                var currentInfo = new byte[resultBlock.Length + info.Length + 1];
                Array.Copy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
                Array.Copy(info, 0, currentInfo, resultBlock.Length, info.Length);
                currentInfo[currentInfo.Length - 1] = (byte)i;
                resultBlock = Hash(prk, currentInfo);
                Array.Copy(resultBlock, 0, result, outputLength - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
                bytesRemaining -= resultBlock.Length;
            }

            return result;
        }

        private static byte[] Hash(byte[] key, byte[] message)
        {
            using (var hmac = new HMACSHA256(key))
            {
                return hmac.ComputeHash(message);
            }
        }
    }
}
