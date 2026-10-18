using System;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    // Port of minio/sio authDecV20.Open — keeps ref header + finalized across packages.
    internal class Dare20DecryptState
    {
        private readonly byte[] _refHeader = new byte[Dare20.HeaderSize];
        private bool _hasRefHeader;

        public Dare20DecryptState()
            : this(0)
        {
        }

        public Dare20DecryptState(uint sequenceNumber)
        {
            SequenceNumber = sequenceNumber;
        }

        public bool Finalized { get; private set; }

        public uint SequenceNumber { get; private set; }

        public int Open(AesGcm cipher, ReadOnlySpan<byte> packageBytes, Span<byte> destination)
        {
            if (Finalized)
            {
                throw new CryptographicException("Unexpected data after final package.");
            }

            if (packageBytes.Length <= Dare20.HeaderSize + Dare20.TagSize)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            if (packageBytes.Length > Dare20.MaxPackageLength)
            {
                throw new CryptographicException("Package too long.");
            }

            // DareHeaderV20 needs a writable Span; copy the 16-byte header to the stack.
            Span<byte> headerBytes = stackalloc byte[Dare20.HeaderSize];
            packageBytes.Slice(start: 0, length: Dare20.HeaderSize).CopyTo(headerBytes);
            var header = new DareHeaderV20(headerBytes);

            if (!_hasRefHeader)
            {
                headerBytes.CopyTo(_refHeader);
                _hasRefHeader = true;
            }

            if (header.Version != Dare20.Version)
            {
                throw new CryptographicException("Unsupported version.");
            }

            if (header.Cipher != Dare20.CipherSuiteAes256Gcm || header.Cipher != _refHeader[1])
            {
                throw new CryptographicException("Unsupported cipher.");
            }

            var expectedPackageLength = Dare20.HeaderSize + header.Length + Dare20.TagSize;
            if (expectedPackageLength != packageBytes.Length)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            if (!header.IsFinal && header.Length != Dare20.MaxPayloadLength)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            if (destination.Length < header.Length)
            {
                throw new ArgumentException("Destination is too short for the decrypted payload.", nameof(destination));
            }

            Span<byte> refNonce = stackalloc byte[12];
            _refHeader.AsSpan(start: 4, length: 12).CopyTo(refNonce);

            if (header.IsFinal)
            {
                Finalized = true;
                refNonce[0] |= 0x80;
            }

            if (!CryptographicOperations.FixedTimeEquals(header.Nonce, refNonce))
            {
                throw new CryptographicException("Nonce mismatch.");
            }

            Span<byte> nonce = stackalloc byte[12];
            Dare20.GetNonceForEncryption(header.Nonce, SequenceNumber, nonce);

            var payload = packageBytes.Slice(start: Dare20.HeaderSize, length: header.Length);
            var tag = packageBytes.Slice(start: Dare20.HeaderSize + header.Length, length: Dare20.TagSize);
            var plaintext = destination.Slice(0, header.Length);
            cipher.Decrypt(nonce, payload, tag, plaintext, header.AddData);

            SequenceNumber++;
            return header.Length;
        }

        public void EnsureFinalized()
        {
            if (!Finalized)
            {
                throw new CryptographicException("Unexpected end of ciphertext before final package.");
            }
        }
    }
}
