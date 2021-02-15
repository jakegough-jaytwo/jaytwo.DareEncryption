using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class Dare20EncryptStream : CryptoStream
    {
        public Dare20EncryptStream(Stream baseStream, long baseStreamLength, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode)
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubheHashedKey(secret, salt, nonce), baseStreamLength), mode)
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
            : base(baseStream, new Dare20EncryptTransform(HkdfHasher.GenerateDoubheHashedKey(secret, salt, nonce), baseStreamLength), mode, leaveOpen)
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
