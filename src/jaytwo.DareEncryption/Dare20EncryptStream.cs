using System.IO;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    public class Dare20EncryptStream : CryptoStream
    {
        public Dare20EncryptStream(Stream baseStream, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce)), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, byte[] secret, byte[] salt, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt)), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, byte[] key, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(key), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce)), mode, leaveOpen)
        {
        }

        public Dare20EncryptStream(Stream baseStream, byte[] secret, byte[] salt, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt)), mode, leaveOpen)
        {
        }

        public Dare20EncryptStream(Stream baseStream, byte[] key, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(key), mode, leaveOpen)
        {
        }

        // baseStreamLength is retained for API compatibility; finalization is EOF-based and ignores it.
        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce), baseStreamLength), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] secret, byte[] salt, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt), baseStreamLength), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] key, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(key, baseStreamLength), mode)
        {
        }

        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce), baseStreamLength), mode, leaveOpen)
        {
        }

        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] secret, byte[] salt, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt), baseStreamLength), mode, leaveOpen)
        {
        }

        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] key, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(key, baseStreamLength), mode, leaveOpen)
        {
        }

        internal Dare20EncryptStream(Stream baseStream, byte[] key, IRandomBytesGenerator nonceGenerator, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(key, nonceGenerator), mode)
        {
        }

        internal Dare20EncryptStream(Stream baseStream, byte[] key, IRandomBytesGenerator nonceGenerator, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(key, nonceGenerator), mode, leaveOpen)
        {
        }

        internal Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] key, IRandomBytesGenerator nonceGenerator, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(key, baseStreamLength, nonceGenerator), mode)
        {
        }

        internal Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] key, IRandomBytesGenerator nonceGenerator, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20EncryptTransform(key, baseStreamLength, nonceGenerator), mode, leaveOpen)
        {
        }
    }
}
