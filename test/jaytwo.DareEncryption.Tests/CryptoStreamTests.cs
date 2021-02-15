using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class CryptoStreamTests
    {
        private static readonly string _passphrase = "foo";
        private static readonly string _salt = "bar";
        private static readonly byte[] _key = HkdfHasher.ComputeHkdfHash(Encoding.UTF8.GetBytes(_passphrase), Encoding.UTF8.GetBytes(_salt));
        private static readonly byte[] _fixedRandomBytesForNonce = Encoding.UTF8.GetBytes("1234567890ab");

        [Fact]
        public async Task CanEncryptDecryptStream()
        {
            // Arrange
            var plainText = "hello world";
            var plainBytes = Encoding.UTF8.GetBytes(plainText);

            // Act
            byte[] decrypted;
            using (var plainStream = new MemoryStream(plainBytes))
            using (var encryptedStream = new Dare20EncryptStream(plainStream, plainStream.Length, _key, CryptoStreamMode.Read))
            using (var decryptedStream = new Dare20DecryptStream(encryptedStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await decryptedStream.CopyToAsync(outputStream);
                decrypted = outputStream.ToArray();
            }

            // Assert
            Assert.Equal(plainBytes, decrypted);
        }

        [Fact]
        public async Task CanEncryptStream()
        {
            // Arrange
            var plainText = "hello world";
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var dare = new Dare20(_key);

            // Act
            byte[] encrypted;
            using (var plainStream = new MemoryStream(plainBytes))
            using (var cryptoStream = new Dare20EncryptStream(plainStream, plainStream.Length, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            // Assert
            var decrypted = dare.DecryptBytes(encrypted);
            Assert.Equal(plainBytes, decrypted);
        }

        [Fact]
        public async Task CanDecryptStream()
        {
            // Arrange
            var plainText = "hello world";
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var dare = new Dare20(_key);
            var encryptedBytes = dare.EncryptBytes(plainBytes);

            // Act
            byte[] decrypted;
            using (var encryptedStream = new MemoryStream(encryptedBytes))
            using (var cryptoStream = new Dare20DecryptStream(encryptedStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                decrypted = outputStream.ToArray();
            }

            // Assert
            Assert.Equal(plainBytes, decrypted);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(25)]
        [InlineData(Dare20.MaxPayloadLength - 1)]
        [InlineData(Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength + 1)]
        [InlineData((Dare20.MaxPayloadLength * 2) - 1)]
        [InlineData(Dare20.MaxPayloadLength * 2)]
        [InlineData((Dare20.MaxPayloadLength * 2) + 1)]
        [InlineData(Dare20.MaxPayloadLength * 10)]
        public async Task CanEncryptAndDecryptQuestionableSizes(int size)
        {
            // Arrange
            var plainBytes = new byte[size];
            RandomNumberGenerator.Fill(plainBytes);
            var dare = new Dare20(_key);

            // Act
            byte[] encrypted;
            using (var plainStream = new MemoryStream(plainBytes))
            using (var bufferedPlainStream = new BufferedStream(plainStream))
            using (var cryptoStream = new Dare20EncryptStream(bufferedPlainStream, plainStream.Length, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                await cryptoStream.CopyToAsync(outputStream);
                encrypted = outputStream.ToArray();
            }

            // Assert
            var decrypted = dare.DecryptBytes(encrypted);
            Assert.Equal(plainBytes, decrypted);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(25)]
        [InlineData(Dare20.MaxPayloadLength - 1)]
        [InlineData(Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength + 1)]
        [InlineData((Dare20.MaxPayloadLength * 2) - 1)]
        [InlineData(Dare20.MaxPayloadLength * 2)]
        [InlineData((Dare20.MaxPayloadLength * 2) + 1)]
        [InlineData(Dare20.MaxPayloadLength * 4)]
        [InlineData(Dare20.MaxPayloadLength * 8)]
        [InlineData(Dare20.MaxPayloadLength * 16)]
        public async Task Dare20EncryptStreamProducesSameOutputAsEncryptBytes(int size)
        {
            // Arrange
            var plainBytes = new byte[size];
            RandomNumberGenerator.Fill(plainBytes);

            var mockRandomBytesGenerator = new Mock<IRandomBytesGenerator>();
            mockRandomBytesGenerator
                .Setup(x => x.GetRandomBytes())
                .Returns(_fixedRandomBytesForNonce);

            var dare = new Dare20(_key, mockRandomBytesGenerator.Object);

            var expectedEncryptedBytes = dare.EncryptBytes(plainBytes);
            var actualEncryptedBytes = default(byte[]);

            using (var plainStream = new MemoryStream(plainBytes))
            using (var cryptoStream = new Dare20EncryptStream(plainStream, plainStream.Length, _key, mockRandomBytesGenerator.Object, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                // Act
                await cryptoStream.CopyToAsync(outputStream);
                actualEncryptedBytes = outputStream.ToArray();
            }

            // Assert
            Assert.Equal(expectedEncryptedBytes, actualEncryptedBytes);
        }

        [Fact]
        public void DisposingBufferedStreamDisposesBaseStream()
        {
            // arrange
            using (var baseStream = new MemoryStream(new byte[Dare20.MaxPayloadLength]))
            using (var bufferedStream = new BufferedStream(baseStream))
            {
                // act
                bufferedStream.Dispose();

                // assert
                Assert.Throws<ObjectDisposedException>(() => baseStream.Length);
            }
        }
    }
}
