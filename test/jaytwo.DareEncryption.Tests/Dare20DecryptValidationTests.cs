using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class Dare20DecryptValidationTests
    {
        private static readonly byte[] _key = CreateKey();
        private static readonly byte[] _fixedNonce = System.Text.Encoding.UTF8.GetBytes("1234567890ab");

        // --- Final-package requirement ---

        [Fact]
        public void DecryptBytes_RejectsTruncatedMultiPackageCiphertext()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 100));
            var truncated = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(truncated));
            Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_RejectsTruncationLeavingOnlyFullNonFinalPackages()
        {
            // Two full packages: first non-final, second final. Drop the final package.
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength * 2));
            Assert.Equal(Dare20.MaxPackageLength * 2, encrypted.Length);

            var truncated = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(truncated));
            Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_RejectsEmptyCiphertext()
        {
            var dare = CreateDare();
            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(Array.Empty<byte>()));
            Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
        }

        [Fact]
        public async Task DecryptStream_RejectsTruncatedMultiPackageCiphertext()
        {
            var dare = CreateDare();
            var truncated = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 100))
                .AsSpan(0, Dare20.MaxPackageLength)
                .ToArray();

            using (var encryptedStream = new MemoryStream(truncated))
            using (var decryptedStream = new Dare20DecryptStream(encryptedStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(
                    () => decryptedStream.CopyToAsync(outputStream));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        // --- No data after final package ---

        [Fact]
        public void DecryptBytes_RejectsTrailingJunkAfterShortFinalPackage()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(new byte[] { 1, 2, 3, 4, 5 });
            var withJunk = new byte[encrypted.Length + 8];
            encrypted.CopyTo(withJunk, 0);

            // Over-long first slice fails length check (sio behavior).
            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(withJunk));
            Assert.Equal("Invalid payload size.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_RejectsSecondPackageAfterFinalFullPackage()
        {
            var dare = CreateDare();
            var first = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength));
            var second = dare.EncryptBytes(new byte[] { 9 });
            var concatenated = new byte[first.Length + second.Length];
            first.CopyTo(concatenated, 0);
            second.CopyTo(concatenated, first.Length);

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(concatenated));
            Assert.Equal("Unexpected data after final package.", ex.Message);
        }

        [Fact]
        public async Task DecryptStream_RejectsSecondPackageAfterFinalFullPackage()
        {
            var dare = CreateDare();
            var first = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength));
            var second = dare.EncryptBytes(new byte[] { 9 });
            var concatenated = new byte[first.Length + second.Length];
            first.CopyTo(concatenated, 0);
            second.CopyTo(concatenated, first.Length);

            using (var encryptedStream = new MemoryStream(concatenated))
            using (var decryptedStream = new Dare20DecryptStream(encryptedStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(
                    () => decryptedStream.CopyToAsync(outputStream));
                Assert.Equal("Unexpected data after final package.", ex.Message);
            }
        }

        // --- Ref-header nonce check ---

        [Fact]
        public void DecryptBytes_RejectsNonceMismatchAcrossPackages()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 50));

            // Flip a non-final bit in the second package nonce so the ref-header compare fails
            // before AEAD (Open checks nonce before Decrypt).
            var secondPackageOffset = Dare20.MaxPackageLength;
            encrypted[secondPackageOffset + 5] ^= 0x01;

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(encrypted));
            Assert.Equal("Nonce mismatch.", ex.Message);
        }

        [Fact]
        public void DecryptState_RejectsNonceMismatchOnFinalPackage()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 10));
            var first = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();
            var second = encrypted.AsSpan(Dare20.MaxPackageLength).ToArray();
            second[5] ^= 0x01;

            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var destination = new byte[Dare20.MaxPayloadLength];
                state.Open(cipher, first, destination);

                var ex = Assert.Throws<CryptographicException>(() => state.Open(cipher, second, destination));
                Assert.Equal("Nonce mismatch.", ex.Message);
            }
        }

        // --- Version / cipher / size validations ---

        [Fact]
        public void DecryptBytes_RejectsWrongVersion()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(new byte[] { 1, 2, 3 });
            encrypted[0] = 0x10;

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(encrypted));
            Assert.Equal("Unsupported version.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_RejectsUnsupportedCipher()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(new byte[] { 1, 2, 3 });
            encrypted[1] = 0x01; // ChaCha20-Poly1305 — not implemented

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(encrypted));
            Assert.Equal("Unsupported cipher.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_RejectsCipherChangedOnLaterPackage()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 20));
            encrypted[Dare20.MaxPackageLength + 1] = 0x01;

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(encrypted));
            Assert.Equal("Unsupported cipher.", ex.Message);
        }

        [Fact]
        public void DecryptBytes_LastPackageHasFinalBit()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 20));
            Assert.True((encrypted[4] & 0x80) == 0x00);
            Assert.True((encrypted[Dare20.MaxPackageLength + 4] & 0x80) == 0x80);
        }

        [Fact]
        public void DecryptState_AcceptsHonestFinalPackageAndSetsFinalized()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(new byte[] { 1, 2, 3, 4 });

            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var plain = new byte[4];
                Assert.Equal(4, state.Open(cipher, encrypted, plain));
                Assert.Equal(new byte[] { 1, 2, 3, 4 }, plain);
                Assert.True(state.Finalized);
                Assert.Equal(1u, state.SequenceNumber);
                state.EnsureFinalized();
            }
        }

        [Fact]
        public void DecryptState_IncrementsSequenceAcrossPackages()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 5));
            var first = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();
            var second = encrypted.AsSpan(Dare20.MaxPackageLength).ToArray();

            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var destination = new byte[Dare20.MaxPayloadLength];
                state.Open(cipher, first, destination);
                Assert.False(state.Finalized);
                Assert.Equal(1u, state.SequenceNumber);

                state.Open(cipher, second, destination);
                Assert.True(state.Finalized);
                Assert.Equal(2u, state.SequenceNumber);
            }
        }

        [Fact]
        public async Task DecryptStream_RejectsEmptyCiphertext()
        {
            using (var encryptedStream = new MemoryStream(Array.Empty<byte>()))
            using (var decryptedStream = new Dare20DecryptStream(encryptedStream, _key, CryptoStreamMode.Read))
            using (var outputStream = new MemoryStream())
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(
                    () => decryptedStream.CopyToAsync(outputStream));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public void DecryptBytes_RejectsDeclaredLengthMismatch()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 1));
            var firstPackage = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();

            // Non-final full package: shrink declared length so span length no longer matches.
            firstPackage[2] = 0x00;
            firstPackage[3] = 0x00; // Length = 1

            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(firstPackage));
            Assert.Equal("Invalid payload size.", ex.Message);
        }

        [Fact]
        public void DecryptState_RejectsNonFinalPackageThatIsNotMaxPayload()
        {
            var dare = CreateDare();
            var shortFinal = dare.EncryptBytes(new byte[] { 1, 2, 3, 4, 5 });
            Assert.True((shortFinal[4] & 0x80) == 0x80);

            // Clear final bit ⇒ non-final + short payload. Size rule runs before nonce compare.
            shortFinal[4] &= 0x7F;

            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var destination = new byte[Dare20.MaxPayloadLength];
                var ex = Assert.Throws<CryptographicException>(() => state.Open(cipher, shortFinal, destination));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public void DecryptState_RejectsPackageTooShort()
        {
            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var tooShort = new byte[Dare20.HeaderSize + Dare20.TagSize];
                var destination = new byte[Dare20.MaxPayloadLength];

                var ex = Assert.Throws<CryptographicException>(() => state.Open(cipher, tooShort, destination));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public void DecryptState_RejectsPackageTooLong()
        {
            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var tooLong = new byte[Dare20.MaxPackageLength + 1];
                var destination = new byte[Dare20.MaxPayloadLength];

                var ex = Assert.Throws<CryptographicException>(() => state.Open(cipher, tooLong, destination));
                Assert.Equal("Package too long.", ex.Message);
            }
        }

        [Fact]
        public void DecryptBytes_RejectsInvalidCiphertextLength()
        {
            var dare = CreateDare();
            var ex = Assert.Throws<CryptographicException>(() => dare.DecryptBytes(new byte[10]));
            Assert.Equal("Invalid ciphertext length.", ex.Message);
        }

        [Fact]
        public void DecryptState_EnsureFinalized_RejectsWhenNeverFinalized()
        {
            var state = new Dare20DecryptState();
            var ex = Assert.Throws<CryptographicException>(() => state.EnsureFinalized());
            Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
        }

        [Fact]
        public void DecryptState_OpenAfterFinal_RejectsUnexpectedData()
        {
            var dare = CreateDare();
            var encrypted = dare.EncryptBytes(new byte[] { 1, 2, 3 });

            using (var cipher = Dare20.CreateAesGcm(_key))
            {
                var state = new Dare20DecryptState();
                var destination = new byte[Dare20.MaxPayloadLength];
                state.Open(cipher, encrypted, destination);
                Assert.True(state.Finalized);

                var ex = Assert.Throws<CryptographicException>(() => state.Open(cipher, encrypted, destination));
                Assert.Equal("Unexpected data after final package.", ex.Message);
            }
        }

        [Fact]
        public void DecryptBytes_StillRoundTripsHonestMultiPackageCiphertext()
        {
            var dare = CreateDare();
            var plain = CreatePlain(Dare20.MaxPayloadLength + 100);
            var encrypted = dare.EncryptBytes(plain);
            Assert.Equal(plain, dare.DecryptBytes(encrypted));
        }

        private static Dare20 CreateDare()
        {
            var mock = new Mock<IRandomBytesGenerator>();
            mock.Setup(x => x.GetRandomBytes()).Returns((byte[])_fixedNonce.Clone());
            return new Dare20(_key, mock.Object);
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
