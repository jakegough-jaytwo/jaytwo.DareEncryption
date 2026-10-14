using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace jaytwo.DareEncryption
{
    // DARE (Data At Rest Encryption) from MinIO's SIO (Secure IO) project: https://github.com/minio/sio
    // DARE 2.0 Spec: https://github.com/minio/sio/issues/16

    public class Dare20
    {
        public const byte Version = 0x20;
        public const byte CipherSuiteAes256Gcm = 0x00;
        public const int HeaderSize = 16;
        public const int TagSize = 16;
        public const int PackageOverheadLength = HeaderSize + TagSize;
        public const int MaxPayloadLength = 65536;
        public const int MinPayloadLength = 1;
        public const int MinPackageLength = MinPayloadLength + PackageOverheadLength;
        public const int MaxPackageLength = MaxPayloadLength + PackageOverheadLength;

        private readonly byte[] _key;
        private readonly IRandomBytesGenerator _randomBytesGenerator;

        public Dare20(byte[] secret, byte[] salt, byte[] nonce)
            : this(HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce))
        {
        }

        public Dare20(byte[] secret, byte[] salt)
            : this(HkdfHasher.ComputeHkdfHash(secret, salt))
        {
        }

        public Dare20(byte[] key)
            : this(key, new Dare20NonceRandomBytesGenerator())
        {
        }

        internal Dare20(byte[] key, IRandomBytesGenerator randomBytesGenerator)
        {
            _key = key;
            _randomBytesGenerator = randomBytesGenerator;
        }

        public static int GetEncryptedLength(int decryptedLength)
            => GetEncryptedLength(decryptedLength, MaxPayloadLength);

        public static int GetEncryptedLength(int decryptedLength, int blockSize)
            => (int)GetEncryptedLength((long)decryptedLength, blockSize);

        public static long GetEncryptedLength(long decryptedLength)
            => GetEncryptedLength(decryptedLength, MaxPayloadLength);

        public static long GetEncryptedLength(long decryptedLength, int blockSize)
        {
            if (decryptedLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(decryptedLength));
            }

            if (blockSize <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            var remainderBytes = decryptedLength % blockSize;
            var wholePackageCount = decryptedLength / blockSize;
            var result = wholePackageCount * (blockSize + PackageOverheadLength);
            if (remainderBytes > 0)
            {
                result += remainderBytes + PackageOverheadLength;
            }

            return result;
        }

        public static int GetDecryptedLength(int encryptedLength, int blockSize)
            => (int)GetDecryptedLength((long)encryptedLength, blockSize);

        public static int GetDecryptedLength(int encryptedLength)
            => GetDecryptedLength(encryptedLength, MaxPackageLength);

        public static long GetDecryptedLength(long encryptedLength)
            => GetDecryptedLength(encryptedLength, MaxPackageLength);

        public static long GetDecryptedLength(long encryptedLength, int blockSize)
        {
            if (encryptedLength < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(encryptedLength));
            }

            if (blockSize <= PackageOverheadLength)
            {
                throw new ArgumentOutOfRangeException(nameof(blockSize));
            }

            if (encryptedLength == 0)
            {
                return 0;
            }

            var remainderBytes = encryptedLength % blockSize;
            if (remainderBytes > 0 && remainderBytes <= PackageOverheadLength)
            {
                throw new ArgumentException("Ciphertext length is not a valid DARE package size.", nameof(encryptedLength));
            }

            var wholePackageCount = encryptedLength / blockSize;
            var result = wholePackageCount * (blockSize - PackageOverheadLength);
            if (remainderBytes > 0)
            {
                result += remainderBytes - PackageOverheadLength;
            }

            return result;
        }

        public byte[] DecryptBytes(byte[] source)
            => DecryptBytes((ReadOnlySpan<byte>)source);

        public byte[] DecryptBytes(ReadOnlySpan<byte> source)
        {
            if (source.Length == 0)
            {
                throw new CryptographicException("Unexpected end of ciphertext before final package.");
            }

            int decryptedLength;
            try
            {
                decryptedLength = GetDecryptedLength(source.Length);
            }
            catch (ArgumentException ex)
            {
                throw new CryptographicException("Invalid ciphertext length.", ex);
            }

            byte[] result = new byte[decryptedLength];
            DecryptBytes(source, result);
            return result;
        }

        public int DecryptBytes(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            if (source.Length == 0)
            {
                throw new CryptographicException("Unexpected end of ciphertext before final package.");
            }

            int decryptedLength;
            try
            {
                decryptedLength = GetDecryptedLength(source.Length);
            }
            catch (ArgumentException ex)
            {
                throw new CryptographicException("Invalid ciphertext length.", ex);
            }

            if (destination.Length < decryptedLength)
            {
                throw new ArgumentException("Destination is too short for the decrypted plaintext.", nameof(destination));
            }

            int readPosition = 0;
            int writePosition = 0;
            var state = new Dare20DecryptState();

            using (var cipher = CreateAesGcm(_key))
            {
                while (readPosition < source.Length)
                {
                    var sliceLength = Math.Min(source.Length - readPosition, MaxPackageLength);
                    var package = source.Slice(readPosition, sliceLength);

                    var plaintextLength = state.Open(cipher, package, destination.Slice(writePosition));
                    readPosition += HeaderSize + TagSize + plaintextLength;
                    writePosition += plaintextLength;
                }
            }

            state.EnsureFinalized();
            return writePosition;
        }

        public byte[] EncryptBytes(byte[] source)
            => EncryptBytes((ReadOnlySpan<byte>)source);

        public byte[] EncryptBytes(ReadOnlySpan<byte> source)
        {
            byte[] result = new byte[GetEncryptedLength(source.Length)];
            EncryptBytes(source, result);
            return result;
        }

        public int EncryptBytes(ReadOnlySpan<byte> source, Span<byte> destination)
        {
            int encryptedLength = GetEncryptedLength(source.Length);
            if (destination.Length < encryptedLength)
            {
                throw new ArgumentException("Destination is too short for the encrypted ciphertext.", nameof(destination));
            }

            var randomBytesForNonce = _randomBytesGenerator.GetRandomBytes();

            int readPosition = 0;
            int writePosition = 0;
            uint packageIndex = 0;

            using (var cipher = CreateAesGcm(_key))
            {
                while (writePosition < encryptedLength)
                {
                    var sliceLength = Math.Min(source.Length - readPosition, MaxPayloadLength);
                    var payload = source.Slice(readPosition, sliceLength);
                    readPosition += sliceLength;

                    var isFinal = sliceLength < MaxPayloadLength || readPosition == source.Length;
                    var packageLength = EncryptPackage(
                        cipher,
                        payload,
                        packageIndex,
                        isFinal,
                        randomBytesForNonce,
                        destination.Slice(writePosition));

                    writePosition += packageLength;
                    packageIndex++;
                }
            }

            return writePosition;
        }

        internal static AesGcm CreateAesGcm(byte[] key)
        {
#if NET8_0_OR_GREATER
            return new AesGcm(key, TagSize);
#else
            return new AesGcm(key);
#endif
        }

        internal static int EncryptBlock(AesGcm cipher, uint packageIndex, byte[] nonce, bool isFinal, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return EncryptPackage(
                cipher,
                inputBuffer.AsSpan(inputOffset, inputCount),
                packageIndex,
                isFinal,
                nonce,
                outputBuffer.AsSpan(outputOffset));
        }

        internal static byte[] EncryptFinalBlock(AesGcm cipher, uint packageIndex, byte[] nonce, byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount <= 0)
            {
                return Array.Empty<byte>();
            }

            var package = new byte[HeaderSize + inputCount + TagSize];
            EncryptPackage(
                cipher,
                inputBuffer.AsSpan(inputOffset, inputCount),
                packageIndex,
                isFinal: true,
                nonce,
                package);
            return package;
        }

        internal static int DecryptBlock(AesGcm cipher, Dare20DecryptState state, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            return state.Open(
                cipher,
                inputBuffer.AsSpan(inputOffset, inputCount),
                outputBuffer.AsSpan(outputOffset));
        }

        internal static byte[] DecryptFinalBlock(AesGcm cipher, Dare20DecryptState state, byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount > 0)
            {
                var package = inputBuffer.AsSpan(inputOffset, inputCount);
                if (package.Length <= HeaderSize + TagSize)
                {
                    throw new CryptographicException("Invalid payload size.");
                }

                var plaintextLength = package.Length - HeaderSize - TagSize;
                var result = new byte[plaintextLength];
                state.Open(cipher, package, result);
                state.EnsureFinalized();
                return result;
            }

            state.EnsureFinalized();
            return Array.Empty<byte>();
        }

        internal static void GetNonceForEncryption(ReadOnlySpan<byte> headerNonce, uint packageIndex, Span<byte> destination)
        {
            // https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L263-L265
            // and
            // https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L198-L200
            /*
var nonce [12]byte
copy(nonce[:], header.Nonce())
binary.LittleEndian.PutUint32(nonce[8:], binary.LittleEndian.Uint32(nonce[8:])^ae.SeqNum)
             */

            if (destination.Length < 12)
            {
                throw new ArgumentException("Nonce destination must be at least 12 bytes.", nameof(destination));
            }

            var nonce = destination.Slice(0, 12);
            headerNonce.Slice(0, 12).CopyTo(nonce);
            var sequence = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(start: 8, length: 4));
            BinaryPrimitives.WriteUInt32LittleEndian(nonce.Slice(start: 8, length: 4), sequence ^ packageIndex);
        }

        internal static int EncryptPackage(
            AesGcm cipher,
            ReadOnlySpan<byte> payload,
            uint packageIndex,
            bool isFinal,
            ReadOnlySpan<byte> randomBytes,
            Span<byte> destination)
        {
            if (payload.Length > MaxPayloadLength)
            {
                throw new InvalidOperationException("Payload too long!");
            }

            if (payload.Length < MinPayloadLength)
            {
                throw new InvalidOperationException("Payload too short!");
            }

            var packageLength = HeaderSize + payload.Length + TagSize;
            if (destination.Length < packageLength)
            {
                throw new ArgumentException("Destination is too short for the encrypted package.", nameof(destination));
            }

            var header = new DareHeaderV20(destination.Slice(0, HeaderSize));
            header.SetVersion();
            header.SetCipher();
            header.SetLength(payload.Length);
            header.SetRand(randomBytes, isFinal);

            Span<byte> nonce = stackalloc byte[12];
            GetNonceForEncryption(header.Nonce, packageIndex, nonce);

            var ciphertext = destination.Slice(HeaderSize, payload.Length);
            var tag = destination.Slice(HeaderSize + payload.Length, TagSize);
            cipher.Encrypt(nonce, payload, ciphertext, tag, header.AddData);

            return packageLength;
        }
    }
}
