using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    public class Dare20NonceRandomBytesGenerator : RandomBytesGenerator
    {
        public const int Dare20NonceRandomBytesLength = 12;

        public Dare20NonceRandomBytesGenerator()
            : base(Dare20NonceRandomBytesLength)
        {
        }
    }
}
