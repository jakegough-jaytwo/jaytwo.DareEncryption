using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class Dare20ByteRangeTests
    {
        private static readonly byte[] _key = CreateKey();

        [Fact]
        public void GetByteRange_MapsOffsetInsideSecondPackage()
        {
            var range = Dare20.GetByteRange(100000, 1000);

            Assert.Equal(1u, range.SequenceNumber);
            Assert.Equal(Dare20.MaxPackageLength, range.CiphertextOffset);
            Assert.Equal(Dare20.MaxPackageLength, range.CiphertextLength);
            Assert.Equal(100000 - Dare20.MaxPayloadLength, range.PlaintextOffsetInSequence);
            Assert.Equal(100000, range.PlaintextOffset);
            Assert.Equal(100999, range.PlaintextInclusiveEnd);
            Assert.Equal(range.CiphertextOffset + range.CiphertextLength - 1, range.CiphertextInclusiveEnd);
            Assert.Equal(1000, range.PlaintextLength);
            Assert.False(range.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_SpansTwoPackagesWhenOffsetIsUnaligned()
        {
            var offset = Dare20.MaxPayloadLength - 10;
            var range = Dare20.GetByteRange(offset, 20);

            Assert.Equal(0u, range.SequenceNumber);
            Assert.Equal(0, range.CiphertextOffset);
            Assert.Equal(Dare20.MaxPackageLength * 2, range.CiphertextLength);
            Assert.Equal(offset, range.PlaintextOffsetInSequence);
            Assert.Equal(20, range.PlaintextLength);
            Assert.False(range.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_ClampsTailAndMarksFinalPackage()
        {
            var plainLength = Dare20.MaxPayloadLength + 50;
            var cipherLength = Dare20.GetEncryptedLength(plainLength);
            var offset = Dare20.MaxPayloadLength + 10;
            var range = Dare20.GetByteRange(offset, 100, cipherLength);

            Assert.Equal(1u, range.SequenceNumber);
            Assert.Equal(Dare20.MaxPackageLength, range.CiphertextOffset);
            Assert.Equal(cipherLength - Dare20.MaxPackageLength, range.CiphertextLength);
            Assert.Equal(10, range.PlaintextOffsetInSequence);
            Assert.Equal(40, range.PlaintextLength);
            Assert.True(range.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_MarksTheOnlyPackageFinal()
        {
            var cipherLength = Dare20.GetEncryptedLength(Dare20.MaxPayloadLength);
            var range = Dare20.GetByteRange(0, 5, cipherLength);

            Assert.Equal(0u, range.SequenceNumber);
            Assert.Equal(0, range.CiphertextOffset);
            Assert.Equal(cipherLength, range.CiphertextLength);
            Assert.Equal(0, range.PlaintextOffsetInSequence);
            Assert.Equal(5, range.PlaintextLength);
            Assert.True(range.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_LeavesAPrefixOfAMultiPackageObjectNonFinal()
        {
            var cipherLength = Dare20.GetEncryptedLength((Dare20.MaxPayloadLength * 2) + 80);
            var range = Dare20.GetByteRange(0, 10, cipherLength);

            Assert.Equal(Dare20.MaxPackageLength, range.CiphertextLength);
            Assert.False(range.IncludesFinalPackage);
        }

        [Theory]
        [InlineData(0, 0)]
        [InlineData(100000, 0)]
        public void GetByteRange_ReturnsEmptyWhenCountIsZero(long offset, long count)
        {
            var range = Dare20.GetByteRange(offset, count);

            Assert.Equal(0, range.CiphertextOffset);
            Assert.Equal(0, range.CiphertextLength);
            Assert.Equal(0u, range.SequenceNumber);
            Assert.Equal(0, range.PlaintextOffsetInSequence);
            Assert.Equal(0, range.PlaintextLength);
            Assert.Equal(offset, range.PlaintextOffset);
            Assert.False(range.IncludesFinalPackage);
            Assert.Throws<InvalidOperationException>(() => range.CiphertextInclusiveEnd);
            Assert.Throws<InvalidOperationException>(() => range.PlaintextInclusiveEnd);
        }

        [Fact]
        public void GetByteRange_ReturnsEmptyAtPlaintextEnd()
        {
            var cipherLength = Dare20.GetEncryptedLength(100);
            var range = Dare20.GetByteRange(100, 0, cipherLength);

            Assert.Equal(0, range.PlaintextLength);
            Assert.Equal(0, range.CiphertextLength);
            Assert.Equal(100, range.PlaintextOffset);
        }

        [Fact]
        public void GetByteRange_RejectsOffsetPastPlaintextEnd()
        {
            var cipherLength = Dare20.GetEncryptedLength(100);

            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(100, 1, cipherLength));
            Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(101, 0, cipherLength));
        }

        [Fact]
        public void GetByteRange_RejectsNegativeArguments()
        {
            Assert.Equal("plaintextOffset", Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(-1, 1)).ParamName);
            Assert.Equal("plaintextLength", Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(0, -1)).ParamName);
            Assert.Equal("ciphertextLength", Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(0, 1, -1)).ParamName);
        }

        [Fact]
        public void GetByteRange_RejectsOffsetThatOverflows()
        {
            Assert.Equal(
                "plaintextLength",
                Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(long.MaxValue, 1)).ParamName);
            var pastLastPackage = ((long)uint.MaxValue + 1) * Dare20.MaxPayloadLength;
            Assert.Equal(
                "plaintextOffset",
                Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(pastLastPackage, 1)).ParamName);

            var lastPackageIndex = (long)uint.MaxValue * Dare20.MaxPayloadLength;
            Assert.Equal(
                "plaintextOffset",
                Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(lastPackageIndex, Dare20.MaxPayloadLength + 1)).ParamName);
        }

        [Fact]
        public void GetByteRange_AllowsTheLastPackageIndex()
        {
            var offset = (long)uint.MaxValue * Dare20.MaxPayloadLength;
            var range = Dare20.GetByteRange(offset, 1);

            Assert.Equal(uint.MaxValue, range.SequenceNumber);
            Assert.Equal(offset, range.PlaintextOffset);
            Assert.Equal(0, range.PlaintextOffsetInSequence);
            Assert.Equal((long)uint.MaxValue * Dare20.MaxPackageLength, range.CiphertextOffset);
            Assert.Equal(Dare20.MaxPackageLength, range.CiphertextLength);
            Assert.False(range.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_AllowsZeroCountAtMaxOffset()
        {
            var range = Dare20.GetByteRange(long.MaxValue, 0);

            Assert.Equal(long.MaxValue, range.PlaintextOffset);
            Assert.Equal(0, range.PlaintextLength);
            Assert.Equal(0, range.CiphertextLength);
        }

        [Fact]
        public void GetByteRange_AlignsPackageBoundaries()
        {
            var payload = Dare20.MaxPayloadLength;
            var package = Dare20.MaxPackageLength;

            var firstByte = Dare20.GetByteRange(0, 1);
            Assert.Equal(0u, firstByte.SequenceNumber);
            Assert.Equal(0, firstByte.CiphertextOffset);
            Assert.Equal(package, firstByte.CiphertextLength);
            Assert.Equal(0, firstByte.PlaintextOffsetInSequence);
            Assert.Equal(1, firstByte.PlaintextLength);

            var lastByteOfPackage = Dare20.GetByteRange(payload - 1, 1);
            Assert.Equal(0u, lastByteOfPackage.SequenceNumber);
            Assert.Equal(package, lastByteOfPackage.CiphertextLength);
            Assert.Equal(payload - 1, lastByteOfPackage.PlaintextOffsetInSequence);

            var firstByteOfNext = Dare20.GetByteRange(payload, 1);
            Assert.Equal(1u, firstByteOfNext.SequenceNumber);
            Assert.Equal(package, firstByteOfNext.CiphertextOffset);
            Assert.Equal(0, firstByteOfNext.PlaintextOffsetInSequence);
            Assert.Equal(package, firstByteOfNext.CiphertextLength);

            var exactPackage = Dare20.GetByteRange(0, payload);
            Assert.Equal(package, exactPackage.CiphertextLength);
            Assert.Equal(payload - 1, exactPackage.PlaintextInclusiveEnd);

            var onePastPackage = Dare20.GetByteRange(0, payload + 1);
            Assert.Equal(package * 2, onePastPackage.CiphertextLength);

            var acrossBoundary = Dare20.GetByteRange(payload - 1, 2);
            Assert.Equal(0u, acrossBoundary.SequenceNumber);
            Assert.Equal(package * 2, acrossBoundary.CiphertextLength);
            Assert.Equal(payload - 1, acrossBoundary.PlaintextOffsetInSequence);
        }

        [Fact]
        public void GetByteRange_UsesObjectLengthAtPackageBoundaries()
        {
            var payload = Dare20.MaxPayloadLength;
            var package = Dare20.MaxPackageLength;
            var twoFullCipher = Dare20.GetEncryptedLength(payload * 2L);

            var firstPackage = Dare20.GetByteRange(0, payload, twoFullCipher);
            Assert.False(firstPackage.IncludesFinalPackage);
            Assert.Equal(package, firstPackage.CiphertextLength);
            Assert.Equal(package - 1, firstPackage.CiphertextInclusiveEnd);

            var whole = Dare20.GetByteRange(0, payload * 2L, twoFullCipher);
            Assert.True(whole.IncludesFinalPackage);
            Assert.Equal(twoFullCipher, whole.CiphertextLength);
            Assert.Equal(twoFullCipher - 1, whole.CiphertextInclusiveEnd);
            Assert.Equal((payload * 2L) - 1, whole.PlaintextInclusiveEnd);

            var lastByte = Dare20.GetByteRange((payload * 2L) - 1, 1, twoFullCipher);
            Assert.Equal(1u, lastByte.SequenceNumber);
            Assert.Equal(package, lastByte.CiphertextOffset);
            Assert.Equal(package, lastByte.CiphertextLength);
            Assert.Equal(payload - 1, lastByte.PlaintextOffsetInSequence);
            Assert.True(lastByte.IncludesFinalPackage);

            var clamped = Dare20.GetByteRange((payload * 2L) - 1, 10, twoFullCipher);
            Assert.Equal(1, clamped.PlaintextLength);
            Assert.Equal((payload * 2L) - 1, clamped.PlaintextInclusiveEnd);
            Assert.True(clamped.IncludesFinalPackage);

            var shortPlain = payload + 7;
            var shortCipher = Dare20.GetEncryptedLength(shortPlain);
            var tailByte = Dare20.GetByteRange(shortPlain - 1, 1, shortCipher);
            Assert.Equal(1u, tailByte.SequenceNumber);
            Assert.Equal(6, tailByte.PlaintextOffsetInSequence);
            Assert.Equal(shortCipher - package, tailByte.CiphertextLength);
            Assert.True(tailByte.IncludesFinalPackage);

            var oneByteCipher = Dare20.GetEncryptedLength(1);
            var onlyByte = Dare20.GetByteRange(0, 1, oneByteCipher);
            Assert.Equal(oneByteCipher, onlyByte.CiphertextLength);
            Assert.Equal(oneByteCipher - 1, onlyByte.CiphertextInclusiveEnd);
            Assert.True(onlyByte.IncludesFinalPackage);
        }

        [Fact]
        public void GetByteRange_HandlesAnEmptyObject()
        {
            var empty = Dare20.GetByteRange(0, 0, 0);
            Assert.Equal(0, empty.PlaintextOffset);
            Assert.Equal(0, empty.PlaintextLength);
            Assert.Equal(0, empty.CiphertextLength);

            Assert.Equal(
                "plaintextOffset",
                Assert.Throws<ArgumentOutOfRangeException>(() => Dare20.GetByteRange(0, 1, 0)).ParamName);
            Assert.Equal(Array.Empty<byte>(), new Dare20(_key).DecryptRange(Array.Empty<byte>(), 0, 0));
        }

        [Fact]
        public void GetByteRange_RejectsCiphertextRemainderAfterAFullPackage()
        {
            var badLength = Dare20.MaxPackageLength + Dare20.PackageOverheadLength;
            var ex = Assert.Throws<ArgumentException>(() => Dare20.GetByteRange(0, 1, badLength));
            Assert.Equal("ciphertextLength", ex.ParamName);
            Assert.IsNotType<ArgumentOutOfRangeException>(ex);
        }

        [Fact]
        public void Dare20ByteRange_RejectsNegativeComponents()
        {
            Assert.Equal("ciphertextOffset", Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20ByteRange(-1, 0, 0, 0, 0, false, 0)).ParamName);
            Assert.Equal("ciphertextLength", Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20ByteRange(0, -1, 0, 0, 0, false, 0)).ParamName);
            Assert.Equal("plaintextOffsetInSequence", Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20ByteRange(0, 0, 0, -1, 0, false, 0)).ParamName);
            Assert.Equal("plaintextLength", Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20ByteRange(0, 0, 0, 0, -1, false, 0)).ParamName);
            Assert.Equal("plaintextOffset", Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20ByteRange(0, 0, 0, 0, 0, false, -1)).ParamName);
        }

        [Fact]
        public void GetByteRange_RejectsCiphertextThatIsNotAPackageSize()
        {
            var ex = Assert.Throws<ArgumentException>(() => Dare20.GetByteRange(0, 1, Dare20.PackageOverheadLength));
            Assert.Equal("ciphertextLength", ex.ParamName);
        }

        [Theory]
        [InlineData(100, 0, 10)]
        [InlineData(100, 0, 1000)]
        [InlineData(100, 90, 50)]
        [InlineData(100, 20, 0)]
        [InlineData(Dare20.MaxPayloadLength, 0, 5)]
        [InlineData(Dare20.MaxPayloadLength, Dare20.MaxPayloadLength - 5, 5)]
        [InlineData(Dare20.MaxPayloadLength + 50, 0, 10)]
        [InlineData(Dare20.MaxPayloadLength + 50, Dare20.MaxPayloadLength - 10, 20)]
        [InlineData(Dare20.MaxPayloadLength + 50, Dare20.MaxPayloadLength + 10, 100)]
        [InlineData(Dare20.MaxPayloadLength * 2, 0, 10)]
        [InlineData(Dare20.MaxPayloadLength * 2, Dare20.MaxPayloadLength, 10)]
        [InlineData(Dare20.MaxPayloadLength * 2, Dare20.MaxPayloadLength - 1, 2)]
        [InlineData((Dare20.MaxPayloadLength * 2) + 80, Dare20.MaxPayloadLength + 10, 100)]
        [InlineData((Dare20.MaxPayloadLength * 2) + 80, (Dare20.MaxPayloadLength * 2) + 50, 40)]
        [InlineData(1, 0, 1)]
        [InlineData(Dare20.MaxPayloadLength * 3, Dare20.MaxPayloadLength - 1, 1)]
        [InlineData(Dare20.MaxPayloadLength * 3, Dare20.MaxPayloadLength, 1)]
        [InlineData(Dare20.MaxPayloadLength * 3, 0, Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength * 3, Dare20.MaxPayloadLength, Dare20.MaxPayloadLength)]
        [InlineData(Dare20.MaxPayloadLength * 3, Dare20.MaxPayloadLength - 10, Dare20.MaxPayloadLength + 20)]
        [InlineData(Dare20.MaxPayloadLength * 2, (Dare20.MaxPayloadLength * 2) - 1, 1)]
        [InlineData(Dare20.MaxPayloadLength * 2, (Dare20.MaxPayloadLength * 2) - 1, 50)]
        public async Task DecryptRange_RoundTripsPlaintextWindow(int plainSize, int offset, int count)
        {
            var plain = CreatePlain(plainSize);
            var dare = new Dare20(_key);
            var encrypted = dare.EncryptBytes(plain);
            var expectedLength = Math.Min(count, plain.Length - offset);
            var expected = plain.AsSpan(offset, expectedLength).ToArray();

            Assert.Equal(expected, dare.DecryptRange(encrypted, offset, count));

            var range = Dare20.GetByteRange(offset, count, encrypted.Length);
            Assert.Equal(expectedLength, range.PlaintextLength);
            Assert.Equal(expected, ReadWindow(encrypted, range, 1));
            Assert.Equal(expected, ReadWindow(encrypted, range, 3));
            Assert.Equal(expected, await ReadWindowAsync(encrypted, range));
        }

        [Fact]
        public void DecryptStream_ReadsMiddlePackageWithoutFinalPackage()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength * 3);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength, Dare20.MaxPayloadLength, encrypted.Length);

            Assert.Equal(1u, range.SequenceNumber);
            Assert.False(range.IncludesFinalPackage);
            Assert.Equal(0, range.PlaintextOffsetInSequence);

            byte[] actual;
            using (var window = OpenWindow(encrypted, range))
            using (var decrypt = new Dare20DecryptStream(window, _key, range.SequenceNumber, range.IncludesFinalPackage, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                decrypt.CopyTo(output);
                actual = output.ToArray();
            }

            Assert.Equal(plain.AsSpan(Dare20.MaxPayloadLength, Dare20.MaxPayloadLength).ToArray(), actual);
        }

        [Fact]
        public void DecryptStream_RejectsMiddleWindowWhenSequenceIsZero()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(Dare20.MaxPayloadLength * 3));
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength, 10, encrypted.Length);

            using (var window = OpenWindow(encrypted, range))
            using (var decrypt = new Dare20DecryptStream(window, _key, sequenceNumber: 0, requireFinalPackage: false, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                Assert.ThrowsAny<CryptographicException>(() => decrypt.CopyTo(output));
            }
        }

        [Fact]
        public void DecryptStream_RejectsMiddleWindowThatRequiresFinalPackage()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(Dare20.MaxPayloadLength * 3));
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength, Dare20.MaxPayloadLength, encrypted.Length);

            using (var window = OpenWindow(encrypted, range))
            using (var decrypt = new Dare20DecryptStream(window, _key, range.SequenceNumber, requireFinalPackage: true, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                var ex = Assert.Throws<CryptographicException>(() => decrypt.CopyTo(output));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsTruncatedCiphertextWindow()
        {
            var plainSize = (Dare20.MaxPayloadLength * 2) + 80;
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(plainSize));
            var offset = Dare20.MaxPayloadLength - 5;
            var range = Dare20.GetByteRange(offset, 10, encrypted.Length);
            var truncated = encrypted.AsSpan((int)range.CiphertextOffset, Dare20.MaxPackageLength).ToArray();

            using (var window = new MemoryStream(truncated))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = Assert.Throws<CryptographicException>(() => ReadAll(stream, 64));
                Assert.Equal(Dare20.CiphertextEndedBeforePlaintextRange, ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsTamperedWindow()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(Dare20.MaxPayloadLength + 20));
            var range = Dare20.GetByteRange(10, 20, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();
            windowBytes[Dare20.HeaderSize + 8] ^= 0xFF;

            using (var window = new MemoryStream(windowBytes))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                Assert.ThrowsAny<CryptographicException>(() => ReadAll(stream, 16));
            }
        }

        [Fact]
        public void DecryptRangeStream_StopEarlyDoesNotThrowOnDispose()
        {
            var plain = CreatePlain((Dare20.MaxPayloadLength * 2) + 40);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var range = Dare20.GetByteRange(0, plain.Length, encrypted.Length);
            Assert.True(range.IncludesFinalPackage);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var buffer = new byte[10];
                var read = stream.Read(buffer, 0, buffer.Length);
                Assert.Equal(10, read);
                Assert.Equal(plain.AsSpan(0, 10).ToArray(), buffer);
            }

            Assert.Throws<ObjectDisposedException>(() => window.Length);
        }

        [Fact]
        public void DecryptRange_RejectsObjectThatEndsOnANonFinalPackage()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(Dare20.MaxPayloadLength * 2));
            var truncated = encrypted.AsSpan(0, Dare20.MaxPackageLength).ToArray();
            var range = Dare20.GetByteRange(0, 10, truncated.Length);
            Assert.True(range.IncludesFinalPackage);

            var ex = Assert.Throws<CryptographicException>(() => new Dare20(_key).DecryptRange(truncated, 0, 10));
            Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);

            var window = new MemoryStream(truncated);
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var readEx = Assert.Throws<CryptographicException>(() => stream.Read(new byte[10], 0, 10));
                Assert.Equal("Unexpected end of ciphertext before final package.", readEx.Message);
            }

            Assert.Throws<ObjectDisposedException>(() => window.Length);
        }

        [Fact]
        public void DecryptRange_RejectsOffsetPastEnd()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            Assert.Throws<ArgumentOutOfRangeException>(() => new Dare20(_key).DecryptRange(encrypted, 32, 1));
        }

        [Fact]
        public void DecryptRangeStream_EmptyRangeDisposesCiphertextWindow()
        {
            var window = new MemoryStream(new byte[] { 1, 2, 3 });
            var range = Dare20.GetByteRange(0, 0);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                Assert.Equal(0, stream.Read(new byte[1], 0, 1));
            }

            Assert.Throws<ObjectDisposedException>(() => window.Position);
        }

        [Fact]
        public void DecryptRangeStream_EmptyRangeDoesNotReadCiphertext()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var window = new MemoryStream(encrypted);
            var range = Dare20.GetByteRange(0, 0, encrypted.Length);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                Assert.Equal(0, stream.Read(new byte[4], 0, 4));
                Assert.Equal(0, window.Position);
            }

            Assert.Equal(0, window.Position);
            window.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_LeaveOpenFalseDisposesCiphertextWindow()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                ReadAll(stream, 8);
            }

            Assert.Throws<ObjectDisposedException>(() => window.Length);
        }

        [Fact]
        public void DecryptRangeStream_LeaveOpenTrueKeepsCiphertextWindowOpen()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                ReadAll(stream, 8);
            }

            Assert.True(window.CanRead);
            window.Dispose();
        }

        [Fact]
        public async Task DecryptRangeStream_ToleratesOneByteCiphertextReads()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength + 25);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var offset = Dare20.MaxPayloadLength - 3;
            var range = Dare20.GetByteRange(offset, 8, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();

            byte[] actual;
            using (var window = new OneByteStream(windowBytes))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            using (var output = new MemoryStream())
            {
                await stream.CopyToAsync(output);
                actual = output.ToArray();
            }

            Assert.Equal(plain.AsSpan(offset, 8).ToArray(), actual);
        }

        [Fact]
        public async Task DecryptRangeStream_AcceptsSecretSaltAndNonce()
        {
            var secret = Encoding.UTF8.GetBytes("secret");
            var salt = Encoding.UTF8.GetBytes("salt");
            var nonce = Encoding.UTF8.GetBytes("nonce");
            var plain = CreatePlain(Dare20.MaxPayloadLength + 25);
            var encrypted = new Dare20(secret, salt, nonce).EncryptBytes(plain);
            var offset = Dare20.MaxPayloadLength - 4;
            var range = Dare20.GetByteRange(offset, 12, encrypted.Length);

            byte[] actual;
            using (var window = OpenWindow(encrypted, range))
            using (var stream = new Dare20DecryptRangeStream(window, secret, salt, nonce, range))
            using (var output = new MemoryStream())
            {
                await stream.CopyToAsync(output);
                actual = output.ToArray();
            }

            Assert.Equal(plain.AsSpan(offset, 12).ToArray(), actual);

            var keptOpen = OpenWindow(encrypted, range);
            using (var stream = new Dare20DecryptRangeStream(keptOpen, secret, salt, nonce, range, leaveOpen: true))
            {
                Assert.Equal(plain.AsSpan(offset, 12).ToArray(), ReadAll(stream, 5));
            }

            Assert.True(keptOpen.CanRead);
            keptOpen.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_AcceptsSecretAndSalt()
        {
            var secret = Encoding.UTF8.GetBytes("secret");
            var salt = Encoding.UTF8.GetBytes("salt");
            var plain = CreatePlain(40);
            var encrypted = new Dare20(secret, salt).EncryptBytes(plain);
            var range = Dare20.GetByteRange(3, 8, encrypted.Length);

            using (var window = OpenWindow(encrypted, range))
            using (var stream = new Dare20DecryptRangeStream(window, secret, salt, range))
            {
                Assert.Equal(plain.AsSpan(3, 8).ToArray(), ReadAll(stream, 3));
            }

            using (var window = OpenWindow(encrypted, range))
            using (var stream = new Dare20DecryptRangeStream(window, secret, salt, range, leaveOpen: true))
            {
                Assert.Equal(plain.AsSpan(3, 8).ToArray(), ReadAll(stream, 3));
            }
        }

        [Fact]
        public void DecryptStream_AcceptsSecretAndSaltForAMiddlePackage()
        {
            var secret = Encoding.UTF8.GetBytes("secret");
            var salt = Encoding.UTF8.GetBytes("salt");
            var plain = CreatePlain(Dare20.MaxPayloadLength + 30);
            var encrypted = new Dare20(secret, salt).EncryptBytes(plain);
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength, 30, encrypted.Length);

            using (var window = OpenWindow(encrypted, range))
            using (var decrypt = new Dare20DecryptStream(window, secret, salt, range.SequenceNumber, range.IncludesFinalPackage, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                decrypt.CopyTo(output);
                Assert.Equal(plain.AsSpan(Dare20.MaxPayloadLength, 30).ToArray(), output.ToArray());
            }

            var keptOpen = OpenWindow(encrypted, range);
            using (var decrypt = new Dare20DecryptStream(keptOpen, secret, salt, range.SequenceNumber, range.IncludesFinalPackage, CryptoStreamMode.Read, leaveOpen: true))
            using (var output = new MemoryStream())
            {
                decrypt.CopyTo(output);
                Assert.Equal(plain.AsSpan(Dare20.MaxPayloadLength, 30).ToArray(), output.ToArray());
            }

            Assert.True(keptOpen.CanRead);
            keptOpen.Dispose();
        }

        [Fact]
        public void DecryptStream_AcceptsSecretSaltAndNonceForAMiddlePackage()
        {
            var secret = Encoding.UTF8.GetBytes("secret");
            var salt = Encoding.UTF8.GetBytes("salt");
            var nonce = Encoding.UTF8.GetBytes("nonce");
            var plain = CreatePlain(Dare20.MaxPayloadLength + 30);
            var encrypted = new Dare20(secret, salt, nonce).EncryptBytes(plain);
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength, 30, encrypted.Length);

            using (var window = OpenWindow(encrypted, range))
            using (var decrypt = new Dare20DecryptStream(window, secret, salt, nonce, range.SequenceNumber, range.IncludesFinalPackage, CryptoStreamMode.Read))
            using (var output = new MemoryStream())
            {
                decrypt.CopyTo(output);
                Assert.Equal(plain.AsSpan(Dare20.MaxPayloadLength, 30).ToArray(), output.ToArray());
            }

            var keptOpen = OpenWindow(encrypted, range);
            using (var decrypt = new Dare20DecryptStream(keptOpen, secret, salt, nonce, range.SequenceNumber, range.IncludesFinalPackage, CryptoStreamMode.Read, leaveOpen: true))
            using (var output = new MemoryStream())
            {
                decrypt.CopyTo(output);
                Assert.Equal(plain.AsSpan(Dare20.MaxPayloadLength, 30).ToArray(), output.ToArray());
            }

            Assert.True(keptOpen.CanRead);
            keptOpen.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_ReadsOneByteAtATime()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength + 25);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var offset = Dare20.MaxPayloadLength - 3;
            var range = Dare20.GetByteRange(offset, 8, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();

            using (var window = new OneByteStream(windowBytes))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                Assert.Equal(plain.AsSpan(offset, 8).ToArray(), ReadAll(stream, 1));
            }
        }

        [Fact]
        public void DecryptRangeStream_ZeroCountReadDoesNotConsumeCiphertext()
        {
            var plain = CreatePlain(32);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var range = Dare20.GetByteRange(4, 8, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                Assert.Equal(0, stream.Read(new byte[4], 0, 0));
                Assert.Equal(0, window.Position);

                var buffer = new byte[8];
                Assert.Equal(3, stream.Read(buffer, 0, 3));
                Assert.Equal(0, stream.Read(buffer, 3, 0));
                Assert.Equal(5, stream.Read(buffer, 3, 5));
                Assert.Equal(plain.AsSpan(4, 8).ToArray(), buffer);
            }

            window.Dispose();
        }

        [Fact]
        public async Task DecryptRangeStream_ZeroCountReadAsyncDoesNotConsumeCiphertext()
        {
            var plain = CreatePlain(32);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var range = Dare20.GetByteRange(4, 8, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                Assert.Equal(0, await stream.ReadAsync(new byte[4], 0, 0));
                Assert.Equal(0, window.Position);

                var buffer = new byte[8];
                Assert.Equal(8, await stream.ReadAsync(buffer, 0, buffer.Length));
                Assert.Equal(plain.AsSpan(4, 8).ToArray(), buffer);
                Assert.Equal(0, await stream.ReadAsync(new byte[1], 0, 1));
            }

            window.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_ReportsStreamCapabilities()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                Assert.True(stream.CanRead);
                Assert.False(stream.CanSeek);
                Assert.False(stream.CanWrite);
                Assert.Throws<NotSupportedException>(() => stream.Length);
                Assert.Throws<NotSupportedException>(() => stream.Position);
                Assert.Throws<NotSupportedException>(() => stream.Position = 1);
                Assert.Throws<NotSupportedException>(() => stream.Seek(0, SeekOrigin.Begin));
                Assert.Throws<NotSupportedException>(() => stream.SetLength(1));
                Assert.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1));
                stream.Flush();
                Assert.Equal(0, window.Position);
            }

            window.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_RejectsUseAfterDispose()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);
            var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true);

            stream.Dispose();
            stream.Dispose();

            Assert.False(stream.CanRead);
            Assert.Throws<ObjectDisposedException>(() => stream.Read(new byte[1], 0, 1));
            Assert.Throws<ObjectDisposedException>(() => stream.Flush());
            Assert.True(window.CanRead);
            window.Dispose();
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsReadAsyncAfterDispose()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);

            var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true);
            stream.Dispose();

            await Assert.ThrowsAsync<ObjectDisposedException>(() => stream.ReadAsync(new byte[1], 0, 1));
            window.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_FinalizerDisposeLeavesTheCiphertextWindowOpen()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);
            var stream = new FinalizerDisposeStream(window, _key, range);

            stream.DisposeFromFinalizer();

            Assert.False(stream.CanRead);
            Assert.True(window.CanRead);
            stream.Dispose();
            Assert.True(window.CanRead);
            window.Dispose();
        }

        [Fact]
        public void DecryptRangeStream_RejectsNullArguments()
        {
            var range = Dare20.GetByteRange(0, 1);
            using (var window = new MemoryStream(new byte[1]))
            {
                Assert.Equal("ciphertextWindow", Assert.Throws<ArgumentNullException>(() => new Dare20DecryptRangeStream(null!, _key, range)).ParamName);
                Assert.Equal("key", Assert.Throws<ArgumentNullException>(() => new Dare20DecryptRangeStream(window, null!, range)).ParamName);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsCancelledRead()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var window = OpenWindow(encrypted, range);
            using (var cancellation = new CancellationTokenSource())
            using (var stream = new Dare20DecryptRangeStream(window, _key, range, leaveOpen: true))
            {
                cancellation.Cancel();
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stream.ReadAsync(new byte[4], 0, 4, cancellation.Token));
                Assert.Equal(0, window.Position);
            }

            window.Dispose();
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsCancellationDuringCiphertextRead()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();
            using (var cancellation = new CancellationTokenSource())
            using (var window = new CancelAfterBytesStream(windowBytes, cancellation, cancelAfter: 1))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stream.ReadAsync(new byte[4], 0, 4, cancellation.Token));
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsEmptyWindowWhenTheFinalPackageIsRequired()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            Assert.True(range.IncludesFinalPackage);

            using (var window = new MemoryStream())
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = Assert.Throws<CryptographicException>(() => stream.Read(new byte[4], 0, 4));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsEmptyWindowWhenTheFinalPackageIsRequiredAsync()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);

            using (var window = new MemoryStream())
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(new byte[4], 0, 4));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsEmptyWindowBeforeTheFinalPackageAsync()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain((Dare20.MaxPayloadLength * 2) + 80));
            var range = Dare20.GetByteRange(Dare20.MaxPayloadLength - 5, 10, encrypted.Length);
            Assert.False(range.IncludesFinalPackage);

            using (var window = new MemoryStream())
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(new byte[4], 0, 4));
                Assert.Equal(Dare20.CiphertextEndedBeforePlaintextRange, ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsMissingFinalPackageAfterAPrefix()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength * 2);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var offset = Dare20.MaxPayloadLength - 4;
            var range = Dare20.GetByteRange(offset, 8, encrypted.Length);
            Assert.True(range.IncludesFinalPackage);
            var onlyFirstPackage = encrypted.AsSpan((int)range.CiphertextOffset, Dare20.MaxPackageLength).ToArray();

            using (var window = new MemoryStream(onlyFirstPackage))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var buffer = new byte[2];
                Assert.Equal(2, stream.Read(buffer, 0, 2));
                Assert.Equal(plain.AsSpan(offset, 2).ToArray(), buffer);
                Assert.Equal(2, stream.Read(buffer, 0, 2));

                var ex = Assert.Throws<CryptographicException>(() => stream.Read(buffer, 0, 2));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsMissingFinalPackageAfterAPrefixAsync()
        {
            var plain = CreatePlain(Dare20.MaxPayloadLength * 2);
            var encrypted = new Dare20(_key).EncryptBytes(plain);
            var offset = Dare20.MaxPayloadLength - 4;
            var range = Dare20.GetByteRange(offset, 8, encrypted.Length);
            var onlyFirstPackage = encrypted.AsSpan((int)range.CiphertextOffset, Dare20.MaxPackageLength).ToArray();

            using (var window = new MemoryStream(onlyFirstPackage))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var buffer = new byte[4];
                Assert.Equal(4, await stream.ReadAsync(buffer, 0, 4));
                Assert.Equal(plain.AsSpan(offset, 4).ToArray(), buffer);

                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(buffer, 0, 4));
                Assert.Equal("Unexpected end of ciphertext before final package.", ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsTruncatedHeader()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var stub = encrypted.AsSpan(0, 5).ToArray();

            using (var window = new MemoryStream(stub))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = Assert.Throws<CryptographicException>(() => stream.Read(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsTruncatedHeaderAsync()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var stub = encrypted.AsSpan(0, 5).ToArray();

            using (var window = new MemoryStream(stub))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsTruncatedPackageBody()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var stub = encrypted.AsSpan(0, Dare20.HeaderSize + 4).ToArray();

            using (var window = new MemoryStream(stub))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = Assert.Throws<CryptographicException>(() => stream.Read(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsTruncatedPackageBodyAsync()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var stub = encrypted.AsSpan(0, Dare20.HeaderSize + 4).ToArray();

            using (var window = new MemoryStream(stub))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public void DecryptRangeStream_RejectsHeaderThatExceedsTheWindow()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();
            windowBytes[2] = 0xFF;
            windowBytes[3] = 0xFF;

            using (var window = new MemoryStream(windowBytes))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = Assert.Throws<CryptographicException>(() => stream.Read(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRangeStream_RejectsHeaderThatExceedsTheWindowAsync()
        {
            var encrypted = new Dare20(_key).EncryptBytes(CreatePlain(32));
            var range = Dare20.GetByteRange(0, 4, encrypted.Length);
            var windowBytes = encrypted.AsSpan((int)range.CiphertextOffset, (int)range.CiphertextLength).ToArray();
            windowBytes[2] = 0xFF;
            windowBytes[3] = 0xFF;

            using (var window = new MemoryStream(windowBytes))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            {
                var ex = await Assert.ThrowsAsync<CryptographicException>(() => stream.ReadAsync(new byte[4], 0, 4));
                Assert.Equal("Invalid payload size.", ex.Message);
            }
        }

        [Fact]
        public async Task DecryptRange_MatchesGoEncryptedSample()
        {
            var plain = await ReadEmbeddedResourceAsync("jaytwo.DareEncryption.Tests.EmbeddedResources.sample1600.jpg");
            var encryptedText = Encoding.UTF8.GetString(await ReadEmbeddedResourceAsync("jaytwo.DareEncryption.Tests.EmbeddedResources.sample1600.goencrypted.b64.txt"));
            var encrypted = Convert.FromBase64String(encryptedText);
            var key = HkdfHasher.ComputeHkdfHash(Encoding.UTF8.GetBytes("foo"), Encoding.UTF8.GetBytes("bar"));
            var dare = new Dare20(key);

            AssertGoRange(dare, encrypted, plain, 0, 32);
            AssertGoRange(dare, encrypted, plain, 1000, 4000);
            AssertGoRange(dare, encrypted, plain, Dare20.MaxPayloadLength - 16, 64);
            AssertGoRange(dare, encrypted, plain, plain.Length - 50, 50);
            AssertGoRange(dare, encrypted, plain, plain.Length - 10, 1000);
        }

        private static void AssertGoRange(Dare20 dare, byte[] encrypted, byte[] plain, int offset, int count)
        {
            var expectedLength = Math.Min(count, plain.Length - offset);
            var expected = plain.AsSpan(offset, expectedLength).ToArray();
            Assert.Equal(expected, dare.DecryptRange(encrypted, offset, count));

            var range = Dare20.GetByteRange(offset, count, encrypted.Length);
            Assert.Equal(expected, ReadWindow(encrypted, range, 7, KeyFromSample()));
        }

        private static byte[] KeyFromSample()
        {
            return HkdfHasher.ComputeHkdfHash(Encoding.UTF8.GetBytes("foo"), Encoding.UTF8.GetBytes("bar"));
        }

        private static byte[] ReadWindow(byte[] encrypted, Dare20ByteRange range, int chunkSize)
        {
            return ReadWindow(encrypted, range, chunkSize, _key);
        }

        private static byte[] ReadWindow(byte[] encrypted, Dare20ByteRange range, int chunkSize, byte[] key)
        {
            using (var window = OpenWindow(encrypted, range))
            using (var stream = new Dare20DecryptRangeStream(window, key, range))
            {
                var actual = ReadAll(stream, chunkSize);
                Assert.Equal(0, stream.Read(new byte[1], 0, 1));
                return actual;
            }
        }

        private static async Task<byte[]> ReadWindowAsync(byte[] encrypted, Dare20ByteRange range)
        {
            using (var window = OpenWindow(encrypted, range))
            using (var stream = new Dare20DecryptRangeStream(window, _key, range))
            using (var output = new MemoryStream())
            {
                await stream.CopyToAsync(output);
                return output.ToArray();
            }
        }

        private static byte[] ReadAll(Stream stream, int chunkSize)
        {
            using (var output = new MemoryStream())
            {
                var buffer = new byte[chunkSize];
                int read;
                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    output.Write(buffer, 0, read);
                }

                return output.ToArray();
            }
        }

        private static MemoryStream OpenWindow(byte[] encrypted, Dare20ByteRange range)
        {
            return new MemoryStream(encrypted, (int)range.CiphertextOffset, (int)range.CiphertextLength, writable: false);
        }

        private static async Task<byte[]> ReadEmbeddedResourceAsync(string resourceName)
        {
            using (var stream = typeof(Dare20ByteRangeTests).Assembly.GetManifestResourceStream(resourceName)
                ?? throw new InvalidOperationException("Embedded resource not found: " + resourceName))
            using (var memoryStream = new MemoryStream())
            {
                await stream.CopyToAsync(memoryStream);
                return memoryStream.ToArray();
            }
        }

        private static byte[] CreatePlain(int size)
        {
            var plain = new byte[size];
            for (int i = 0; i < plain.Length; i++)
            {
                plain[i] = (byte)(i % 251);
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

        private sealed class OneByteStream : Stream
        {
            private readonly byte[] _data;
            private int _offset;

            public OneByteStream(byte[] data)
            {
                _data = data;
            }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (count == 0 || _offset >= _data.Length)
                {
                    return 0;
                }

                buffer[offset] = _data[_offset];
                _offset++;
                return 1;
            }

            public override long Seek(long offset, SeekOrigin origin)
                => throw new NotSupportedException();

            public override void SetLength(long value)
                => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();
        }

        private sealed class CancelAfterBytesStream : Stream
        {
            private readonly byte[] _data;
            private readonly CancellationTokenSource _cancellation;
            private readonly int _cancelAfter;
            private int _offset;

            public CancelAfterBytesStream(byte[] data, CancellationTokenSource cancellation, int cancelAfter)
            {
                _data = data;
                _cancellation = cancellation;
                _cancelAfter = cancelAfter;
            }

            public override bool CanRead => true;

            public override bool CanSeek => false;

            public override bool CanWrite => false;

            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get { throw new NotSupportedException(); }
                set { throw new NotSupportedException(); }
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                if (count == 0 || _offset >= _data.Length)
                {
                    return 0;
                }

                buffer[offset] = _data[_offset];
                _offset++;
                if (_offset >= _cancelAfter)
                {
                    _cancellation.Cancel();
                }

                return 1;
            }

            public override long Seek(long offset, SeekOrigin origin)
                => throw new NotSupportedException();

            public override void SetLength(long value)
                => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
                => throw new NotSupportedException();
        }

        private sealed class FinalizerDisposeStream : Dare20DecryptRangeStream
        {
            public FinalizerDisposeStream(Stream ciphertextWindow, byte[] key, Dare20ByteRange range)
                : base(ciphertextWindow, key, range)
            {
            }

            public void DisposeFromFinalizer()
            {
                Dispose(false);
            }
        }
    }
}
