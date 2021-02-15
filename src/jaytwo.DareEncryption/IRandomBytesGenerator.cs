using System;
using System.Collections.Generic;
using System.Text;

namespace jaytwo.DareEncryption
{
    public interface IRandomBytesGenerator
    {
        byte[] GetRandomBytes();
    }
}
