# jaytwo.DareEncryption

[![NuGet Version](https://img.shields.io/nuget/v/jaytwo.DareEncryption.svg?style=flat&logo=nuget)](https://www.nuget.org/packages/jaytwo.DareEncryption)
[![NuGet Downloads](https://img.shields.io/nuget/dt/jaytwo.DareEncryption.svg?style=flat)](https://www.nuget.org/packages/jaytwo.DareEncryption)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://mit-license.org/)

Source: [github.com/jakegough-jaytwo/jaytwo.DareEncryption](https://github.com/jakegough-jaytwo/jaytwo.DareEncryption)

Targets `net8.0`, `net6.0`, and `netstandard2.1`.

A .NET implementation of Data At Rest Encryption mostly compatible with [MinIO's SIO](https://github.com/minio/sio).  If you want to refactor a Go app to
.NET but that Go app depends on the `minio/sio` package, that's the reason this package exists. Thanks to .NET Standard 2.1 for adding support for AES-GCM
in `System.Security.Cryptography.AesGcm`.  Also, I say this is _mostly_ compatible because technically DARE can support ChaCha20-Poly1305 encryption, but I've
only implemented AES-GCM, which is the default in the Go package anyway.  Also apparently there are or may be multiple versions of DARE, but so far I've only
needed to care about the DARE 2.0 spec (which, as far as I can tell, [was also referred to as v1.1](https://github.com/minio/sio/issues/16)).

And yes, saying _DARE Encryption_ is redundant.  If you hate it when people say _ATM Machine_, you'll hate that I named the package `DareEncryption`.

## Installation

Add the NuGet package

```
PM> Install-Package jaytwo.DareEncryption
```

## Usage

```csharp
// This unit test is probably the best illustration of the basic functionality:
public void EncryptAndDecryptTest(byte[] key, byte[] plainBytes)
{
    // Arrange
    var dare = new Dare20(key);

    // Act
    var encryptedBytes = dare.EncryptBytes(plainBytes);
    var decryptedBytes = dare.DecryptBytes(encryptedBytes);

    // Assert
    Assert.Equal(plainBytes, decryptedBytes);
}

// The best keys are hash-derived keys, for that we use HKDF hashing.

// Using a secret + salt:
var passphrase = "foo";
var salt = "bar";
var key = HkdfHasher.ComputeHkdfHash(Encoding.UTF8.GetBytes(passphrase), Encoding.UTF8.GetBytes(salt));

// Or you can use a double-hashed secret + salt + nonce.
var passphrase = "foo";
var salt = "bar";
var nonce = "banana";
var key = HkdfHasher.GenerateDoubleHashedKey(Encoding.UTF8.GetBytes(passphrase), Encoding.UTF8.GetBytes(salt), Encoding.UTF8.GetBytes(nonce));

// You don't actually need to invoke the HkdfHasher, you can just pass them into the constructors of the Dare20, Dare20EncryptStream, or Dare20DecryptStream.
var passphraseBytes = Encoding.UTF8.GetBytes("foo");
var saltBytes = Encoding.UTF8.GetBytes("bar");
var nonceBytes = Encoding.UTF8.GetBytes("banana");
var dare = new Dare20(passphraseBytes, saltBytes, nonceBytes);
var encryptedBytes = dare.EncryptBytes(plainBytes);
```

### Notes About Streams

Streams can be quirky when dealing with encryption.  Some things that you take for granted when working with byte arrays may not always apply
when working with streams.  For example, you may not know the length of the stream when you start reading it.  Also, a stream may be forward-only
readable, so you can't revisit any previously-read bytes from the stream.  Lastly, the other end of the stream can close the stream even if you
weren't done with it yet.

Since DARE encrypts the final block/package differently than the preceding blocks/packages, something has to know when you're on the last bit.
Encrypt streams now finalize that last DARE package on EOF, so you no longer need an accurate plaintext length just to get the final package right.
(There are still overloads that take `baseStreamLength` for compatibility, but they ignore it for finalization.)  Decrypt still needs a complete
ciphertext that ends with a final package — if a stream is forward-only readable and may unexpectedly close on you after you've read the final byte
(like in an HTTP stream), there's still room for a sneaky bug to hide if the stream length is evenly divisible by the package length.  If you are
reading and writing to streams (e.g. reading from a large HTTP request to save to an encrypted object store), I recommend wrapping your source
streams in a `BufferedStream` before passing them to the decrypt streams.

```csharp

// if you need to know the length of the encrypted/decrypted stream before encrypting/decrypting the data:
// var encryptedLength = Dare20.GetEncryptedLength(plainLength);
// var decryptedLength = Dare20.GetDecryptedLength(encryptedLength);

public async Task SavePlainStreamToEncryptedStream(Stream inputPlainStream, byte[] key, Stream outputEncryptedStream)
{
    using (inputPlainStream)
    using (var cryptoStream = new Dare20EncryptStream(inputPlainStream, key, CryptoStreamMode.Read))
    using (outputEncryptedStream)
    {
        await cryptoStream.CopyToAsync(outputEncryptedStream);
    }
}

public Stream GetEncryptedStream(Stream inputPlainStream, byte[] key)
{
    // no usings because we need the streams to be accessible after we return the cryptoStream
    // (by default disposing the CryptoStream disposes the underlying input Stream)
    return new Dare20EncryptStream(inputPlainStream, key, CryptoStreamMode.Read);
}

public async Task SaveEncryptedStreamToDecryptedStream(Stream inputEncryptedStream, byte[] key, Stream outputDecryptedStream)
{
    using (inputEncryptedStream)
    using (var bufferedEncryptedStream = new BufferedStream(inputEncryptedStream))
    using (var cryptoStream = new Dare20DecryptStream(bufferedEncryptedStream, key, CryptoStreamMode.Read))
    using (outputDecryptedStream)
    {
        await cryptoStream.CopyToAsync(outputDecryptedStream);
    }
}

public Stream GetDecryptedStream(Stream inputEncryptedStream, byte[] key)
{
    // no usings because we need the streams to be accessible after we return the cryptoStream
    // (by default disposing the CryptoStream disposes the underlying BufferedStream, and disposing the BufferedStream disposes the underlying input Stream)
    var bufferedEncryptedStream = new BufferedStream(inputEncryptedStream);
    var cryptoStream = new Dare20DecryptStream(bufferedEncryptedStream, key, CryptoStreamMode.Read);
    return cryptoStream;
}
```

---

Made with &hearts; by Jake
