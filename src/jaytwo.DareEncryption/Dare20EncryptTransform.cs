using System;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    public class Dare20EncryptTransform : ICryptoTransform
    {
        private readonly AesGcm _cipher;
        private readonly byte[] _nonce;
        private readonly byte[] _pendingPayload = new byte[Dare20.MaxPayloadLength];
        private int _pendingCount;
        private uint _packageIndex;

        public Dare20EncryptTransform(byte[] key)
            : this(key, new Dare20NonceRandomBytesGenerator())
        {
        }

        // baseStreamLength is retained for API compatibility; finalization is EOF-based and ignores it.
        public Dare20EncryptTransform(byte[] key, long baseStreamLength)
            : this(key, new Dare20NonceRandomBytesGenerator())
        {
            _ = baseStreamLength;
        }

        internal Dare20EncryptTransform(byte[] key, IRandomBytesGenerator randomBytesGenerator)
            : this(key, randomBytesGenerator.GetRandomBytes())
        {
        }

        internal Dare20EncryptTransform(byte[] key, long baseStreamLength, IRandomBytesGenerator randomBytesGenerator)
            : this(key, randomBytesGenerator.GetRandomBytes())
        {
            _ = baseStreamLength;
        }

        internal Dare20EncryptTransform(byte[] key, byte[] nonce)
        {
            _cipher = Dare20.CreateAesGcm(key);
            _nonce = nonce;
        }

        internal Dare20EncryptTransform(byte[] key, long baseStreamLength, byte[] nonce)
            : this(key, nonce)
        {
            _ = baseStreamLength;
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
            if (inputCount <= 0)
            {
                return 0;
            }

            if (_pendingCount > 0)
            {
                var written = Dare20.EncryptBlock(
                    _cipher,
                    _packageIndex,
                    _nonce,
                    isFinal: false,
                    _pendingPayload,
                    0,
                    _pendingCount,
                    outputBuffer,
                    outputOffset);
                _packageIndex++;

                Buffer.BlockCopy(inputBuffer, inputOffset, _pendingPayload, 0, inputCount);
                _pendingCount = inputCount;
                return written;
            }

            Buffer.BlockCopy(inputBuffer, inputOffset, _pendingPayload, 0, inputCount);
            _pendingCount = inputCount;
            return 0;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (_pendingCount == 0 && inputCount == 0)
            {
                return Array.Empty<byte>();
            }

            if (_pendingCount > 0 && inputCount > 0)
            {
                var nonFinalLength = Dare20.HeaderSize + _pendingCount + Dare20.TagSize;
                var finalLength = Dare20.HeaderSize + inputCount + Dare20.TagSize;
                var combined = new byte[nonFinalLength + finalLength];

                Dare20.EncryptBlock(
                    _cipher,
                    _packageIndex,
                    _nonce,
                    isFinal: false,
                    _pendingPayload,
                    0,
                    _pendingCount,
                    combined,
                    0);
                _packageIndex++;

                Dare20.EncryptBlock(
                    _cipher,
                    _packageIndex,
                    _nonce,
                    isFinal: true,
                    inputBuffer,
                    inputOffset,
                    inputCount,
                    combined,
                    nonFinalLength);
                _pendingCount = 0;
                _packageIndex++;

                return combined;
            }

            if (_pendingCount > 0)
            {
                var result = Dare20.EncryptFinalBlock(_cipher, _packageIndex, _nonce, _pendingPayload, 0, _pendingCount);
                _pendingCount = 0;
                _packageIndex++;
                return result;
            }

            var finalOnly = Dare20.EncryptFinalBlock(_cipher, _packageIndex, _nonce, inputBuffer, inputOffset, inputCount);
            _packageIndex++;
            return finalOnly;
        }
    }
}
