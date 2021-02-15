using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace jaytwo.DareEncryption
{
    // DARE (Data At Rest Encryption) from Minio's SIO (Secuire IO) project: https://github.com/minio/sio
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
            : this(HkdfHasher.GenerateDoubheHashedKey(secret, salt, nonce))
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
            var remainderBytes = decryptedLength % blockSize;
            var wholePackageCount = (long)Math.Floor((double)decryptedLength / blockSize);
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
            var remainderBytes = encryptedLength % blockSize;
            var wholePackageCount = (long)Math.Floor((double)encryptedLength / blockSize);
            var result = wholePackageCount * (blockSize - PackageOverheadLength);
            if (remainderBytes > 0)
            {
                result += remainderBytes - PackageOverheadLength;
            }

            return result;
        }

        public byte[] DecryptBytes(Span<byte> source)
        {
            int decryptedLength = GetDecryptedLength(source.Length);
            byte[] result = new byte[decryptedLength];

            int readPosition = 0;
            int writePosition = 0;
            uint packageIndex = 0;

            using (var cipher = new AesGcm(_key))
            {
                while (writePosition < decryptedLength)
                {
                    var sliceLength = Math.Min(source.Length - readPosition, MaxPackageLength);
                    var package = source.Slice(readPosition, sliceLength);
                    readPosition += sliceLength;

                    var decryptedPackage = DecryptPackage(cipher, package, packageIndex);

                    decryptedPackage.CopyTo(result, writePosition);
                    writePosition += decryptedPackage.Length;

                    packageIndex++;
                }
            }

            return result;
        }

        public byte[] EncryptBytes(byte[] source)
            => EncryptBytes(new Span<byte>(source));

        public byte[] EncryptBytes(Span<byte> source)
        {
            var randomBytesForNonce = _randomBytesGenerator.GetRandomBytes();

            int encryptedLength = GetEncryptedLength(source.Length);
            byte[] result = new byte[encryptedLength];

            int readPosition = 0;
            int writePosition = 0;
            uint packageIndex = 0;

            using (var cipher = new AesGcm(_key))
            {
                while (writePosition < encryptedLength)
                {
                    var sliceLength = Math.Min(source.Length - readPosition, MaxPayloadLength);
                    var payload = source.Slice(readPosition, sliceLength);
                    readPosition += sliceLength;

                    var isFinal = sliceLength < MaxPayloadLength || readPosition == source.Length;
                    var encryptedPackage = GetEncryptedPackage(cipher, payload, packageIndex, isFinal, randomBytesForNonce);

                    encryptedPackage.CopyTo(result, writePosition);
                    writePosition += encryptedPackage.Length;

                    packageIndex++;
                }
            }

            return result;
        }

        internal static int EncryptBlock(AesGcm cipher, uint packageIndex, byte[] nonce, bool isFinal, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var payload = inputBuffer.AsSpan(inputOffset, inputCount);
            var encryptedBlock = GetEncryptedPackage(cipher, payload, packageIndex, isFinal, nonce);
            encryptedBlock.CopyTo(outputBuffer, outputOffset);
            return encryptedBlock.Length;
        }

        internal static byte[] EncryptFinalBlock(AesGcm cipher, uint packageIndex, byte[] nonce, byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount > 0)
            {
                var payload = inputBuffer.AsSpan(inputOffset, inputCount);
                return GetEncryptedPackage(cipher, payload, packageIndex, true, nonce);
            }
            else
            {
                return new byte[] { };
            }
        }

        internal static int DecryptBlock(AesGcm cipher, uint packageIndex, byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            var package = inputBuffer.AsSpan(inputOffset, inputCount);
            var decryptedBlock = DecryptPackage(cipher, package, packageIndex);
            decryptedBlock.CopyTo(outputBuffer, outputOffset);
            return decryptedBlock.Length;
        }

        internal static byte[] DecryptFinalBlock(AesGcm cipher, uint packageIndex, byte[] inputBuffer, int inputOffset, int inputCount)
        {
            if (inputCount > 0)
            {
                var package = inputBuffer.AsSpan(inputOffset, inputCount);
                return DecryptPackage(cipher, package, packageIndex);
            }
            else
            {
                return new byte[] { };
            }
        }

        private static byte[] GetEncryptedPackage(AesGcm cipher, Span<byte> payload, uint packageIndex, bool isFinal, byte[] randomBytes)
        {
            if (payload.Length > MaxPayloadLength)
            {
                throw new InvalidOperationException("Payload too long!");
            }

            if (payload.Length < MinPayloadLength)
            {
                throw new InvalidOperationException("Payload too short!");
            }

            var header = DareHeaderV20.Create();
            header.SetVersion();
            header.SetCipher();
            header.SetLength(payload.Length);
            header.SetRand(randomBytes, isFinal);

            var nonce = GetNonceForEncryption(header.Nonce, packageIndex);

            var encrypted = new byte[payload.Length];
            var tag = new byte[TagSize];

            cipher.Encrypt(nonce, payload, encrypted, tag, header.AddData);

            var package = new byte[HeaderSize + encrypted.Length + TagSize];
            header.Buffer.CopyTo(package.AsSpan(start: 0, length: HeaderSize));
            encrypted.CopyTo(package.AsSpan(start: HeaderSize, length: encrypted.Length));
            tag.CopyTo(package.AsSpan(start: HeaderSize + encrypted.Length, length: TagSize));

            return package;
        }

        private static byte[] DecryptPackage(AesGcm cipher, Span<byte> packageBytes, uint packageIndex)
        {
            var package = new DarePackageV20(packageBytes);

            var header = package.Header;
            var refNonce = header.Nonce;

            if (header.IsFinal)
            {
                refNonce[0] |= 0x80;
            }

            if (ConstantTimeCompare(refNonce, header.Nonce) != 1)
            {
                throw new Exception("errNonceMismatch");
            }

            var nonce = GetNonceForEncryption(header.Nonce, packageIndex);
            var tag = package.Ciphertext.Slice(start: header.Length, length: TagSize);
            var decryptedBytes = new byte[package.Payload.Length];
            cipher.Decrypt(nonce, package.Payload, tag, decryptedBytes, header.AddData);

            return decryptedBytes;
        }

        private static int ConstantTimeCompare(Span<byte> a, Span<byte> b)
        {
            if (a.Length != b.Length)
            {
                return 0;
            }
            else
            {
                for (int i = 0; i < a.Length; i++)
                {
                    if (a[i] != b[i])
                    {
                        return 0;
                    }
                }
            }

            return 1;
        }

        private static byte[] GetNonceForEncryption(Span<byte> headerNonce, uint packageIndex)
        {
            // https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L263-L265
            // and
            // https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L198-L200
            /*
var nonce [12]byte
copy(nonce[:], header.Nonce())
binary.LittleEndian.PutUint32(nonce[8:], binary.LittleEndian.Uint32(nonce[8:])^ae.SeqNum)
             */

            var nonce = new byte[12];
            headerNonce.CopyTo(nonce);
            BitConverter.GetBytes(BitConverter.ToUInt32(nonce, 8) ^ packageIndex).CopyTo(nonce, 8);
            return nonce;
        }
    }
}
