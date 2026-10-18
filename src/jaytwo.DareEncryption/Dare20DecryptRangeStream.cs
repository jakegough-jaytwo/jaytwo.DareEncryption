using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace jaytwo.DareEncryption
{
    public class Dare20DecryptRangeStream : Stream
    {
        private readonly Stream _ciphertext;
        private readonly AesGcm? _cipher;
        private readonly Dare20DecryptState _state;
        private readonly byte[]? _packageBuffer;
        private readonly byte[]? _plaintextBuffer;
        private readonly bool _leaveOpen;
        private readonly bool _includesFinalPackage;
        private readonly long _expectedCiphertextLength;
        private long _ciphertextBytesRead;
        private long _skipRemaining;
        private long _remaining;
        private int _plaintextOffset;
        private int _plaintextCount;
        private bool _disposed;

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] key, Dare20ByteRange range)
            : this(ciphertextWindow, key, range, leaveOpen: false)
        {
        }

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] key, Dare20ByteRange range, bool leaveOpen)
        {
            _ciphertext = ciphertextWindow ?? throw new ArgumentNullException(nameof(ciphertextWindow));
            _ = key ?? throw new ArgumentNullException(nameof(key));
            _leaveOpen = leaveOpen;
            _includesFinalPackage = range.IncludesFinalPackage;
            _expectedCiphertextLength = range.CiphertextLength;
            _skipRemaining = range.PlaintextOffsetInSequence;
            _remaining = range.PlaintextLength;
            _state = new Dare20DecryptState(range.SequenceNumber);

            if (range.PlaintextLength == 0)
            {
                _cipher = null;
                _packageBuffer = null;
                _plaintextBuffer = null;
                return;
            }

            _cipher = Dare20.CreateAesGcm(key);
            _packageBuffer = new byte[Dare20.MaxPackageLength];
            _plaintextBuffer = new byte[Dare20.MaxPayloadLength];
        }

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] secret, byte[] salt, Dare20ByteRange range)
            : this(ciphertextWindow, HkdfHasher.ComputeHkdfHash(secret, salt), range)
        {
        }

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] secret, byte[] salt, Dare20ByteRange range, bool leaveOpen)
            : this(ciphertextWindow, HkdfHasher.ComputeHkdfHash(secret, salt), range, leaveOpen)
        {
        }

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] secret, byte[] salt, byte[] nonce, Dare20ByteRange range)
            : this(ciphertextWindow, HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce), range)
        {
        }

        public Dare20DecryptRangeStream(Stream ciphertextWindow, byte[] secret, byte[] salt, byte[] nonce, Dare20ByteRange range, bool leaveOpen)
            : this(ciphertextWindow, HkdfHasher.GenerateDoubleHashedKey(secret, salt, nonce), range, leaveOpen)
        {
        }

        public override bool CanRead => !_disposed;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        private byte[] PackageBuffer => _packageBuffer ?? throw new InvalidOperationException("Plaintext range is empty.");

        private byte[] PlaintextBuffer => _plaintextBuffer ?? throw new InvalidOperationException("Plaintext range is empty.");

        private AesGcm Cipher => _cipher ?? throw new InvalidOperationException("Plaintext range is empty.");

        public override void Flush()
        {
            ThrowIfDisposed();
            _ciphertext.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
            => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            ThrowIfDisposed();
            if (_remaining == 0 || buffer.Length == 0)
            {
                return 0;
            }

            var written = 0;
            while (written < buffer.Length && _remaining > 0)
            {
                DiscardBufferedSkip();
                if (_skipRemaining > 0)
                {
                    ReadNextPackage();
                    continue;
                }

                if (_plaintextCount == 0)
                {
                    ReadNextPackage();
                }

                var count = (int)Math.Min(buffer.Length - written, Math.Min(_plaintextCount, _remaining));
                PlaintextBuffer.AsSpan(_plaintextOffset, count).CopyTo(buffer.Slice(written, count));
                _plaintextOffset += count;
                _plaintextCount -= count;
                _remaining -= count;
                written += count;
            }

            return written;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (_remaining == 0 || buffer.Length == 0)
            {
                return 0;
            }

            var written = 0;
            while (written < buffer.Length && _remaining > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                DiscardBufferedSkip();
                if (_skipRemaining > 0 || _plaintextCount == 0)
                {
                    await ReadNextPackageAsync(cancellationToken).ConfigureAwait(false);
                    continue;
                }

                var count = (int)Math.Min(buffer.Length - written, Math.Min(_plaintextCount, _remaining));
                PlaintextBuffer.AsSpan(_plaintextOffset, count).CopyTo(buffer.Span.Slice(written, count));
                _plaintextOffset += count;
                _plaintextCount -= count;
                _remaining -= count;
                written += count;
            }

            return written;
        }

        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        public override void SetLength(long value)
            => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
            => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing && !_disposed)
            {
                _disposed = true;
                try
                {
                    _cipher?.Dispose();
                }
                finally
                {
                    if (!_leaveOpen)
                    {
                        _ciphertext.Dispose();
                    }
                }
            }

            _disposed = true;
            base.Dispose(disposing);
        }

        private void ReadNextPackage()
        {
            AcceptPackage(ReadPackageLength());
        }

        private async Task ReadNextPackageAsync(CancellationToken cancellationToken)
        {
            var packageLength = await ReadPackageLengthAsync(cancellationToken).ConfigureAwait(false);
            AcceptPackage(packageLength);
        }

        private void AcceptPackage(int packageLength)
        {
            var written = _state.Open(Cipher, PackageBuffer.AsSpan(0, packageLength), PlaintextBuffer);
            if (written <= 0)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            if (_includesFinalPackage && _ciphertextBytesRead >= _expectedCiphertextLength && !_state.Finalized)
            {
                throw new CryptographicException("Unexpected end of ciphertext before final package.");
            }

            _plaintextOffset = 0;
            _plaintextCount = written;
        }

        private int ReadPackageLength()
        {
            var headerRead = ReadCiphertext(PackageBuffer, 0, Dare20.HeaderSize);
            if (headerRead == 0)
            {
                throw EndOfWindow();
            }

            if (headerRead < Dare20.HeaderSize)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            var payloadLength = new DareHeaderV20(PackageBuffer.AsSpan(0, Dare20.HeaderSize)).Length;
            var rest = payloadLength + Dare20.TagSize;
            if (ReadCiphertext(PackageBuffer, Dare20.HeaderSize, rest) < rest)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            return Dare20.HeaderSize + rest;
        }

        private async Task<int> ReadPackageLengthAsync(CancellationToken cancellationToken)
        {
            var headerRead = await ReadCiphertextAsync(PackageBuffer, 0, Dare20.HeaderSize, cancellationToken).ConfigureAwait(false);
            if (headerRead == 0)
            {
                throw EndOfWindow();
            }

            if (headerRead < Dare20.HeaderSize)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            var payloadLength = new DareHeaderV20(PackageBuffer.AsSpan(0, Dare20.HeaderSize)).Length;
            var rest = payloadLength + Dare20.TagSize;
            var restRead = await ReadCiphertextAsync(PackageBuffer, Dare20.HeaderSize, rest, cancellationToken).ConfigureAwait(false);
            if (restRead < rest)
            {
                throw new CryptographicException("Invalid payload size.");
            }

            return Dare20.HeaderSize + rest;
        }

        private int ReadCiphertext(byte[] buffer, int offset, int count)
        {
            var read = 0;
            while (read < count)
            {
                var remainingExpected = _expectedCiphertextLength - _ciphertextBytesRead;
                if (remainingExpected <= 0)
                {
                    break;
                }

                var toRead = (int)Math.Min(count - read, remainingExpected);
                var n = _ciphertext.Read(buffer, offset + read, toRead);
                if (n == 0)
                {
                    break;
                }

                read += n;
                _ciphertextBytesRead += n;
            }

            return read;
        }

        private async Task<int> ReadCiphertextAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var read = 0;
            while (read < count)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var remainingExpected = _expectedCiphertextLength - _ciphertextBytesRead;
                if (remainingExpected <= 0)
                {
                    break;
                }

                var toRead = (int)Math.Min(count - read, remainingExpected);
                var n = await _ciphertext.ReadAsync(buffer, offset + read, toRead, cancellationToken).ConfigureAwait(false);
                if (n == 0)
                {
                    break;
                }

                read += n;
                _ciphertextBytesRead += n;
            }

            return read;
        }

        private void DiscardBufferedSkip()
        {
            if (_skipRemaining <= 0 || _plaintextCount <= 0)
            {
                return;
            }

            var count = (int)Math.Min(_plaintextCount, _skipRemaining);
            _plaintextOffset += count;
            _plaintextCount -= count;
            _skipRemaining -= count;
        }

        private CryptographicException EndOfWindow()
        {
            if (_includesFinalPackage && !_state.Finalized)
            {
                return new CryptographicException("Unexpected end of ciphertext before final package.");
            }

            return new CryptographicException(Dare20.CiphertextEndedBeforePlaintextRange);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Dare20DecryptRangeStream));
            }
        }
    }
}
