using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class Dare20DecryptTransform : ICryptoTransform
    {
        private readonly AesGcm _cipher;
        private uint _packageIndex = 0;

        public Dare20DecryptTransform(byte[] key)
        {
            _cipher = new AesGcm(key);
        }

        public bool CanReuseTransform => false;

        public bool CanTransformMultipleBlocks => false;

        public int InputBlockSize => Dare20.MaxPackageLength;

        public int OutputBlockSize => Dare20.MaxPayloadLength;

        public void Dispose()
        {
            _cipher.Dispose();
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var result = Dare20.DecryptBlock(_cipher, _packageIndex, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            _packageIndex++;
            return result;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            var result = Dare20.DecryptFinalBlock(_cipher, _packageIndex, inputBuffer, inputOffset, inputCount);
            _packageIndex++;
            return result;
        }
    }
}
