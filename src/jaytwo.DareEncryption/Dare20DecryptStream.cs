using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class Dare20DecryptStream : CryptoStream
    {
        public Dare20DecryptStream(Stream baseStream, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode)
            : base(baseStream, new Dare20DecryptTransform(HkdfHasher.GenerateDoubheHashedKey(secret, salt, nonce)), mode)
        {
        }

        public Dare20DecryptStream(Stream baseStream, byte[] secret, byte[] salt, CryptoStreamMode mode)
            : base(baseStream, new Dare20DecryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt)), mode)
        {
        }

        public Dare20DecryptStream(Stream baseStream, byte[] key, CryptoStreamMode mode)
            : base(baseStream, new Dare20DecryptTransform(key), mode)
        {
        }

        public Dare20DecryptStream(Stream baseStream, byte[] secret, byte[] salt, byte[] nonce, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20DecryptTransform(HkdfHasher.GenerateDoubheHashedKey(secret, salt, nonce)), mode, leaveOpen)
        {
        }

        public Dare20DecryptStream(Stream baseStream, byte[] secret, byte[] salt, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20DecryptTransform(HkdfHasher.ComputeHkdfHash(secret, salt)), mode, leaveOpen)
        {
        }

        public Dare20DecryptStream(Stream baseStream, byte[] key, CryptoStreamMode mode, bool leaveOpen)
            : base(baseStream, new Dare20DecryptTransform(key), mode, leaveOpen)
        {
        }
    }
}
