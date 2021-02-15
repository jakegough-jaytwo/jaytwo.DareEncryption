using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace jaytwo.DareEncryption.Tests
{
    public class HkdfHasherTests
    {
        [Fact]
        public void GenerateDoubheHashedKeyWorks()
        {
            // Arrange
            var expectedKey = Convert.FromBase64String("qgiRsHMXSllgbqvFFYGVwYNYph2rlZAFf7XzHag1DuY=");
            var passphraseBytes = Encoding.UTF8.GetBytes("foo");
            var saltBytes = Encoding.UTF8.GetBytes("bar");
            var nonceBytes = Encoding.UTF8.GetBytes("banana");

            // Act
            var generatedKey = HkdfHasher.GenerateDoubheHashedKey(passphraseBytes, saltBytes, nonceBytes);

            // Assert
            Assert.Equal(expectedKey, generatedKey);

            /*
// https://play.golang.org/

package main

package main
import (
    "crypto/sha256"
    "fmt"
    "io"
    b64 "encoding/base64"
    hkdf "golang.org/x/crypto/hkdf"
)

func main() {
    fmt.Println(GetKey("foo", "bar", "banana")) // returns "qgiRsHMXSllgbqvFFYGVwYNYph2rlZAFf7XzHag1DuY="
}

func GetKey(passphrase string, salt string, nonce string) (string, error) {
    var firstPass [32]byte
    keyhkdf := hkdf.New(sha256.New, []byte(passphrase), []byte(salt), nil)
    io.ReadFull(keyhkdf, firstPass[:])
    keyhkdf = hkdf.New(sha256.New, firstPass[:], []byte(nonce), nil)
    var secondPass [32]byte
    io.ReadFull(keyhkdf, secondPass[:])
    base64Key := b64.StdEncoding.EncodeToString(secondPass[:])
    return base64Key , nil
}
             */
        }

        [Fact]
        public void GetHkdfKeyWorks()
        {
            // Arrange
            var expectedKey = Convert.FromBase64String("m6E+F3FDAmDcoPBJV2IsEk9Mw3o9l57PJ99lFMhCZtA=");
            var passphraseBytes = Encoding.UTF8.GetBytes("foo");
            var saltBytes = Encoding.UTF8.GetBytes("bar");

            // Act
            var generatedKey = HkdfHasher.ComputeHkdfHash(passphraseBytes, saltBytes);

            // Assert
            Assert.Equal(expectedKey, generatedKey);

            /*
// https://play.golang.org/

package main

import (
    "crypto/sha256"
    "fmt"
    "io"
    b64 "encoding/base64"
    hkdf "golang.org/x/crypto/hkdf"
)

func main() {
    fmt.Println(GetBase64Key("foo", "bar")) // returns "m6E+F3FDAmDcoPBJV2IsEk9Mw3o9l57PJ99lFMhCZtA="
}

func GetBase64Key(passphrase string, salt string) (string, error) {
    var key [32]byte
    keyhkdf := hkdf.New(sha256.New, []byte(passphrase), []byte(salt), nil)
    if _, err := io.ReadFull(keyhkdf, key[:]); err != nil {
        return "", err
    }

    base64Key := b64.StdEncoding.EncodeToString(key[:])
    return base64Key , nil
}
             */
        }
    }
}
