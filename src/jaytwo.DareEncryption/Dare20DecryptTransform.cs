using System;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    public class Dare20DecryptTransform : ICryptoTransform
    {
        private readonly AesGcm _cipher;
        private readonly Dare20DecryptState _state = new Dare20DecryptState();

        public Dare20DecryptTransform(byte[] key)
        {
            _cipher = Dare20.CreateAesGcm(key);
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
            return Dare20.DecryptBlock(_cipher, _state, inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            return Dare20.DecryptFinalBlock(_cipher, _state, inputBuffer, inputOffset, inputCount);
        }
    }
}
