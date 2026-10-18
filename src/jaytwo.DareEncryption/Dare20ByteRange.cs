using System;

namespace jaytwo.DareEncryption
{
    public readonly struct Dare20ByteRange
    {
        internal Dare20ByteRange(
            long ciphertextOffset,
            long ciphertextLength,
            uint sequenceNumber,
            int plaintextOffsetInSequence,
            long plaintextLength,
            bool includesFinalPackage,
            long plaintextOffset)
        {
            if (ciphertextOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(ciphertextOffset));
            }

            if (ciphertextLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(ciphertextLength));
            }

            if (plaintextOffsetInSequence < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(plaintextOffsetInSequence));
            }

            if (plaintextLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(plaintextLength));
            }

            if (plaintextOffset < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(plaintextOffset));
            }

            CiphertextOffset = ciphertextOffset;
            CiphertextLength = ciphertextLength;
            SequenceNumber = sequenceNumber;
            PlaintextOffsetInSequence = plaintextOffsetInSequence;
            PlaintextLength = plaintextLength;
            IncludesFinalPackage = includesFinalPackage;
            PlaintextOffset = plaintextOffset;
        }

        public long CiphertextOffset { get; }

        public long CiphertextLength { get; }

        public long CiphertextInclusiveEnd
        {
            get
            {
                if (CiphertextLength == 0)
                {
                    throw new InvalidOperationException("Byte range does not include ciphertext.");
                }

                return CiphertextOffset + CiphertextLength - 1;
            }
        }

        public uint SequenceNumber { get; }

        public int PlaintextOffsetInSequence { get; }

        public long PlaintextOffset { get; }

        public long PlaintextLength { get; }

        public long PlaintextInclusiveEnd
        {
            get
            {
                if (PlaintextLength == 0)
                {
                    throw new InvalidOperationException("Byte range does not include plaintext.");
                }

                return PlaintextOffset + PlaintextLength - 1;
            }
        }

        public bool IncludesFinalPackage { get; }
    }
}
