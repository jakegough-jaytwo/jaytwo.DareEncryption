using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class Dare20EncryptTransform : ICryptoTransform
    {
        private readonly AesGcm _cipher;
        private uint _packageIndex = 0;
        private byte[] _nonce;
        private long _encryptedStreamLength;
        private long _totalBytesTransformed;

        public Dare20EncryptTransform(byte[] key, long encryptedStreamLength)
            : this(key, encryptedStreamLength, new Dare20NonceRandomBytesGenerator())
        {
        }

        internal Dare20EncryptTransform(byte[] key, long encryptedStreamLength, IRandomBytesGenerator randomBytesGenerator)
            : this(key, encryptedStreamLength, randomBytesGenerator.GetRandomBytes())
        {
        }

        internal Dare20EncryptTransform(byte[] key, long encryptedStreamLength, byte[] nonce)
        {
            _cipher = new AesGcm(key);
            _nonce = nonce;
            _encryptedStreamLength = encryptedStreamLength;
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => false;

        public int InputBlockSize => Dare20.MaxPayloadLength;

        public int OutputBlockSize => Dare20.MaxPackageLength;

        public void Dispose()
        {
            _cipher.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var isFinalBlock = _totalBytesTransformed + inputCount == _encryptedStreamLength;
            var result = Dare20.EncryptBlock(_cipher, _packageIndex, _nonce, isFinalBlock, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            _totalBytesTransformed += inputCount;
            _packageIndex++;
            return result;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var result = Dare20.EncryptFinalBlock(_cipher, _packageIndex, _nonce, inputBuffer, inputOffset, inputCount);
            _totalBytesTransformed += inputCount;
            _packageIndex++;
            return result;
        }
    }
}
