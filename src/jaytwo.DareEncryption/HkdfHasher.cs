using System;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    public class HkdfHasher
    {
        private const int HashLength = 32;

        public static byte[] GenerateDoubleHashedKey(byte[] secret, byte[] salt, byte[] nonce)
        {
            var firstPass = ComputeHkdfHash(secret, salt);
            var secondPass = ComputeHkdfHash(firstPass, nonce);
            return secondPass;
        }

        // see also: https://github.com/golang/crypto/blob/master/hkdf/hkdf.go#L90-L93
        public static byte[] ComputeHkdfHash(byte[] secret, byte[] salt, byte[] info = null)
        {
            var pseudoRandomKey = Extract(secret, salt);
            return Expand(pseudoRandomKey, info, HashLength);
        }

        private static byte[] Extract(byte[] ikm, byte[] salt)
        {
            return Hash(salt, ikm);
        }

        // https://gist.github.com/charlesportwoodii/09ffd6868c2a6e55826c4d5ebb509651
        private static byte[] Expand(byte[] prk, byte[] info, int outputLength)
        {
            info = info ?? Array.Empty<byte>();
            var result = new byte[outputLength];

            // T(0) is empty; each round is HMAC(PRK, T(i-1) || info || counter).
            // For SHA-256 / 32-byte output this is a single round.
            Span<byte> previous = stackalloc byte[HashLength];
            int previousLength = 0;
            int offset = 0;
            byte counter = 1;
            int maxMessageLength = HashLength + info.Length + 1;
            Span<byte> messageBuffer = maxMessageLength <= 64
                ? stackalloc byte[maxMessageLength]
                : new byte[maxMessageLength];

            using (var hmac = new HMACSHA256(prk))
            {
                while (offset < outputLength)
                {
                    int messageLength = previousLength + info.Length + 1;
                    Span<byte> message = messageBuffer.Slice(0, messageLength);

                    if (previousLength > 0)
                    {
                        previous.Slice(0, previousLength).CopyTo(message);
                    }

                    if (info.Length > 0)
                    {
                        info.CopyTo(message.Slice(previousLength));
                    }

                    message[messageLength - 1] = counter++;

                    if (!hmac.TryComputeHash(message.Slice(0, messageLength), previous, out previousLength)
                        || previousLength != HashLength)
                    {
                        throw new CryptographicException("HKDF expand failed.");
                    }

                    int toCopy = Math.Min(previousLength, outputLength - offset);
                    previous.Slice(0, toCopy).CopyTo(result.AsSpan(offset));
                    offset += toCopy;
                }
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
