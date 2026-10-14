using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class Dare20LengthAndEndianTests
    {
        private static readonly byte[] _key = CreateKey();
        private static readonly byte[] _fixedNonce = System.Text.Encoding.UTF8.GetBytes("1234567890ab");

        // --- GetDecryptedLength / GetEncryptedLength hardening ---

        [Theory]
        [InlineData(1)]
        [InlineData(10)]
        [InlineData(31)]
        [InlineData(Dare20.PackageOverheadLength)]
        public void GetDecryptedLength_RejectsRemainderOnlyOverheadSizes(int encryptedLength)
        {
            var ex = Assert.Throws<ArgumentException>(() => Dare20.GetDecryptedLength(encryptedLength));
            Assert.Contains("valid DARE package size", ex.Message, StringComparison.Ordinal);
        }

        [Theory]
        [InlineData(Dare20.MaxPackageLength + 1)]
        [InlineData(Dare20.MaxPackageLength + Dare20.PackageOverheadLength)]
        public void GetDecryptedLength_RejectsInvalidRemainderAfterFullPackages(int encryptedLength)
        {
            Assert.Throws<ArgumentException>(() => Dare20.GetDecryptedLength(encryptedLength));
        }

        [Fact]
        public void GetDecryptedLength_RejectsNegativeLength()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetDecryptedLength(-1));
        }

        [Fact]
        public void GetDecryptedLength_RejectsBlockSizeTooSmall()
        {
            Assert.Throws<ArgumentOutOfRangeException>(
                () => Dare20.GetDecryptedLength(Dare20.MaxPackageLength, Dare20.PackageOverheadLength));
            Assert.Throws<ArgumentOutOfRangeException>(
                () => Dare20.GetDecryptedLength(Dare20.MaxPackageLength, 0));
        }

        [Fact]
        public void GetEncryptedLength_RejectsNegativeLength()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetEncryptedLength(-1));
        }

        [Fact]
        public void GetEncryptedLength_RejectsNonPositiveBlockSize()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetEncryptedLength(10, 0));
            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetEncryptedLength(10, -1));
        }

        [Fact]
        public void GetDecryptedLength_ReturnsZeroForEmpty()
        {
            Assert.Equal(0, Dare20.GetDecryptedLength(0));
        }

        [Theory]
        [InlineData(1)]
        [InlineData(25)]
        [InlineData(Dare20.MaxPayloadLength - 1)]
        [InlineData(Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength + 1)]
        [InlineData(Dare20.MaxPayloadLength * 2)]
        public void GetEncryptedAndDecryptedLength_RoundTripWithEncryptBytes(int plainLength)
        {
            var dare = CreateDare();
            var plain = CreatePlain(plainLength);
            var encrypted = dare.EncryptBytes(plain);

            Assert.Equal(encrypted.Length, Dare20.GetEncryptedLength(plainLength));
            Assert.Equal(plainLength, Dare20.GetDecryptedLength(encrypted.Length));
        }

        [Fact]
        public void DecryptBytes_WrapsInvalidLengthAsCryptographicException()
        {
            var dare = CreateDare();
            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(new byte[10]));
            Assert.Equal("Invalid ciphertext length.", ex.Message);
            Assert.IsType<ArgumentException>(ex.InnerException);
        }

        // --- Little-endian header / nonce ---

        [Theory]
        [InlineData(1)]
        [InlineData(256)]
        [InlineData(257)]
        [InlineData(Dare20.MaxPayloadLength)]
        public void Header_SetLength_UsesLittleEndian(int length)
        {
            var header = DareHeaderV20.Create();
            header.SetLength(length);

            Assert.Equal(length, header.Length);
            Assert.Equal(
                (ushort)(length - 1),
                BinaryPrimitives.ReadUInt16LittleEndian(header.Buffer.Slice(2, 2)));
        }

        [Fact]
        public void Header_SetLength_WritesExpectedBytesFor256()
        {
            var header = DareHeaderV20.Create();
            header.SetLength(256);

            // length-1 = 255 = 0x00FF little-endian
            Assert.Equal(0xFF, header.Buffer[2]);
            Assert.Equal(0x00, header.Buffer[3]);
        }

        [Fact]
        public void Header_SetLength_WritesExpectedBytesFor257()
        {
            var header = DareHeaderV20.Create();
            header.SetLength(257);

            // length-1 = 256 = 0x0100 little-endian
            Assert.Equal(0x00, header.Buffer[2]);
            Assert.Equal(0x01, header.Buffer[3]);
        }

        [Fact]
        public void GetNonceForEncryption_XorsSequenceLittleEndian()
        {
            var headerNonce = new byte[12];
            BinaryPrimitives.WriteUInt32LittleEndian(headerNonce.AsSpan(8, 4), 0x01020304);

            Span<byte> nonce = stackalloc byte[12];
            Dare20.GetNonceForEncryption(headerNonce, packageIndex: 0x00000001, nonce);
            var sequence = BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4));

            Assert.Equal(0x01020305u, sequence);
        }

        [Fact]
        public void GetNonceForEncryption_XorsAcrossByteBoundaryLittleEndian()
        {
            var headerNonce = new byte[12];
            BinaryPrimitives.WriteUInt32LittleEndian(headerNonce.AsSpan(8, 4), 0x000000FF);

            Span<byte> nonce = stackalloc byte[12];
            Dare20.GetNonceForEncryption(headerNonce, packageIndex: 0x00000100, nonce);
            Assert.Equal(0x000001FFu, BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4)));
            Assert.Equal(0xFF, nonce[8]);
            Assert.Equal(0x01, nonce[9]);
            Assert.Equal(0x00, nonce[10]);
            Assert.Equal(0x00, nonce[11]);
        }

        [Fact]
        public void EncryptBytes_MultiPackage_UsesLittleEndianSequenceInNonce()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 1));

            // Both packages share the same header nonce bytes before seq XOR; decrypt round-trip
            // already proves seq XOR is correct. Also assert package headers share rand (sans final bit).
            var firstNonce = encrypted.AsSpan(4, 12).ToArray();
            var secondNonce = encrypted.AsSpan(Dare20.MaxPackageLength + 4, 12).ToArray();
            firstNonce[0] &= 0x7F;
            secondNonce[0] &= 0x7F;
            Assert.Equal(firstNonce, secondNonce);
            Assert.True((encrypted[Dare20.MaxPackageLength + 4] & 0x80) == 0x80);
        }

        // --- EOF-based encrypt stream finalization ---

        [Fact]
        public async Task EncryptStream_IgnoresIncorrectPlaintextLengthForFinalBit()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength + 50);
            var dare = CreateDare();
            var expected = dare.EncryptBytes(plain);

            byte[] actual;
            using (var plainStream = new MemoryStream(plain))
            using (var cryptoStream = new Dare20EncryptStream(
                plainStream,
                plainStream.Length + 9999,
                _key,
                CreateNonceGenerator(),
                CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                actual = outputStream.ToArray();
            }

            Assert.Equal(expected, actual);
            Assert.Equal(plain, dare.DecryptBytes(actual));
        }

        [Fact]
        public async Task EncryptStream_WorksWithoutLengthArgument()
        {
            var plain = CreatePlain(100);
            var dare = CreateDare();

            byte[] encrypted;
            using (var plainStream = new MemoryStream(plain))
            using (var cryptoStream = new Dare20EncryptStream(plainStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            Assert.Equal(plain, new Dare20(_key).DecryptBytes(encrypted));
        }

        [Theory]
        [InlineData(Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength * 2)]
        [InlineData(Dare20.MaxPayloadLength + 1)]
        [InlineData((Dare20.MaxPayloadLength * 2) + 1)]
        public async Task EncryptStream_MatchesEncryptBytes_ForBoundarySizes(int size)
        {
            var plain = CreatePlain(size);
            var dare = CreateDare();

            byte[] encrypted;
            using (var plainStream = new MemoryStream(plain))
            using (var cryptoStream = new Dare20EncryptStream(plainStream, _key, CreateNonceGenerator(), CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            Assert.Equal(dare.EncryptBytes(plain), encrypted);
            Assert.Equal(plain, dare.DecryptBytes(encrypted));
        }

        private static Dare20 CreateDare()
        {
            return new Dare20(_key, CreateNonceGenerator());
        }

        private static IRandomBytesGenerator CreateNonceGenerator()
        {
            var mock = new Mock<IRandomBytesGenerator>();
            mock.Setup(x => x.GetRandomBytes()).Returns((byte[])_fixedNonce.Clone());
            return mock.Object;
        }

        private static byte[] CreatePlain(int size)
        {
            var plain = new byte[size];
            RandomNumberGenerator.Fill(plain);
            return plain;
        }

        private static byte[] CreateKey()
        {
            var key = new byte[32];
            for (int i = 0; i < key.Length; i++)
            {
                key[i] = (byte)i;
            }

            return key;
        }
    }
}
