using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class Dare20EncryptTransformTests
    {
        private static readonly byte[] _key = CreateKey();
        private static readonly byte[] _fixedNonce = System.Text.Encoding.UTF8.GetBytes("1234567890ab");

        [Fact]
        public void TransformBlock_BuffersFirstFullBlockWithoutEmitting()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var input = CreatePlain(Dare20.MaxPayloadLength);
                var output = new byte[Dare20.MaxPackageLength];

                var written = transform.TransformBlock(input, 0, input.Length, output, 0);

                Assert.Equal(0, written);
            }
        }

        [Fact]
        public void TransformFinalBlock_AfterBufferedFullBlock_EmitsFinalPackage()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var input = CreatePlain(Dare20.MaxPayloadLength);
                var output = new byte[Dare20.MaxPackageLength];
                transform.TransformBlock(input, 0, input.Length, output, 0);

                var finalPackage = transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                Assert.Equal(Dare20.MaxPackageLength, finalPackage.Length);
                Assert.True((finalPackage[4] & 0x80) == 0x80);
                Assert.Equal(input, new Dare20(_key, CreateNonceGenerator()).DecryptBytes(finalPackage));
            }
        }

        [Fact]
        public void TransformBlock_SecondFullBlock_EmitsNonFinalFirstPackage()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var first = CreatePlain(Dare20.MaxPayloadLength);
                var second = CreatePlain(Dare20.MaxPayloadLength);
                var output = new byte[Dare20.MaxPackageLength];

                Assert.Equal(0, transform.TransformBlock(first, 0, first.Length, output, 0));

                var written = transform.TransformBlock(second, 0, second.Length, output, 0);
                Assert.Equal(Dare20.MaxPackageLength, written);
                Assert.True((output[4] & 0x80) == 0x00);

                var finalPackage = transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                Assert.True((finalPackage[4] & 0x80) == 0x80);

                var combined = new byte[output.Length + finalPackage.Length];
                Buffer.BlockCopy(output, 0, combined, 0, output.Length);
                Buffer.BlockCopy(finalPackage, 0, combined, output.Length, finalPackage.Length);

                var expectedPlain = new byte[first.Length + second.Length];
                Buffer.BlockCopy(first, 0, expectedPlain, 0, first.Length);
                Buffer.BlockCopy(second, 0, expectedPlain, first.Length, second.Length);
                Assert.Equal(expectedPlain, new Dare20(_key, CreateNonceGenerator()).DecryptBytes(combined));
            }
        }

        [Fact]
        public void TransformFinalBlock_WithPendingAndRemainder_EmitsNonFinalThenFinal()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var full = CreatePlain(Dare20.MaxPayloadLength);
                var remainder = CreatePlain(50);
                var output = new byte[Dare20.MaxPackageLength];
                transform.TransformBlock(full, 0, full.Length, output, 0);

                var packages = transform.TransformFinalBlock(remainder, 0, remainder.Length);

                Assert.Equal(Dare20.MaxPackageLength + Dare20.HeaderSize + remainder.Length + Dare20.TagSize, packages.Length);
                Assert.True((packages[4] & 0x80) == 0x00);
                Assert.True((packages[Dare20.MaxPackageLength + 4] & 0x80) == 0x80);

                var expectedPlain = new byte[full.Length + remainder.Length];
                Buffer.BlockCopy(full, 0, expectedPlain, 0, full.Length);
                Buffer.BlockCopy(remainder, 0, expectedPlain, full.Length, remainder.Length);
                Assert.Equal(expectedPlain, new Dare20(_key, CreateNonceGenerator()).DecryptBytes(packages));
            }
        }

        [Fact]
        public void TransformFinalBlock_ShortPayloadOnly_EmitsSingleFinalPackage()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var input = CreatePlain(25);
                var packages = transform.TransformFinalBlock(input, 0, input.Length);

                Assert.Equal(Dare20.HeaderSize + input.Length + Dare20.TagSize, packages.Length);
                Assert.True((packages[4] & 0x80) == 0x80);
                Assert.Equal(input, new Dare20(_key, CreateNonceGenerator()).DecryptBytes(packages));
            }
        }

        [Fact]
        public void TransformFinalBlock_Empty_ReturnsEmpty()
        {
            using (var transform = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                Assert.Empty(transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0));
            }
        }

        [Fact]
        public void LengthTakingConstructor_DoesNotAffectFinalization()
        {
            using (var ignoredLength = new Dare20EncryptTransform(_key, baseStreamLength: 1, _fixedNonce))
            using (var noLength = new Dare20EncryptTransform(_key, _fixedNonce))
            {
                var input = CreatePlain(Dare20.MaxPayloadLength + 10);
                var outA = new byte[Dare20.MaxPackageLength];
                var outB = new byte[Dare20.MaxPackageLength];

                ignoredLength.TransformBlock(input, 0, Dare20.MaxPayloadLength, outA, 0);
                noLength.TransformBlock(input, 0, Dare20.MaxPayloadLength, outB, 0);

                var finalA = ignoredLength.TransformFinalBlock(input, Dare20.MaxPayloadLength, 10);
                var finalB = noLength.TransformFinalBlock(input, Dare20.MaxPayloadLength, 10);

                Assert.Equal(finalB, finalA);
            }
        }

        [Fact]
        public async Task EncryptStream_LastPackageHasFinalBit_ForExactMultiple()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength * 2);
            byte[] encrypted;
            using (var plainStream = new MemoryStream(plain))
            using (var cryptoStream = new Dare20EncryptStream(plainStream, _key, CreateNonceGenerator(), CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            Assert.Equal(Dare20.MaxPackageLength * 2, encrypted.Length);
            Assert.True((encrypted[4] & 0x80) == 0x00);
            Assert.True((encrypted[Dare20.MaxPackageLength + 4] & 0x80) == 0x80);
        }

        [Fact]
        public async Task EncryptStream_WrongLength_StillSetsFinalBitOnLastPackage()
        {
            var plain = CreatePlain(100);
            byte[] encrypted;
            using (var plainStream = new MemoryStream(plain))
            using (var cryptoStream = new Dare20EncryptStream(
                plainStream,
                baseStreamLength: 1,
                _key,
                CreateNonceGenerator(),
                CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            Assert.True((encrypted[4] & 0x80) == 0x80);
            Assert.Equal(plain, new Dare20(_key, CreateNonceGenerator()).DecryptBytes(encrypted));
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
            for (int i = 0; i < size; i++)
            {
                plain[i] = (byte)(i & 0xFF);
            }

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
