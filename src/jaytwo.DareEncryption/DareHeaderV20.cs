#pragma warning disable SA1201 // Elements must appear in the correct order
#pragma warning disable SA1502 // Element must not be on a single line
#pragma warning disable SA1206 // Declaration keywords must follow order

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace jaytwo.DareEncryption
{
    // port of: https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L45-L63

    /*
type headerV20 []byte

func (h headerV20) Version() byte         { return h[0] }
func (h headerV20) SetVersion()           { h[0] = Version20 }
func (h headerV20) Cipher() byte          { return h[1] }
func (h headerV20) SetCipher(cipher byte) { h[1] = cipher }
func (h headerV20) Length() int           { return int(binary.LittleEndian.Uint16(h[2:4])) + 1 }
func (h headerV20) SetLength(length int)  { binary.LittleEndian.PutUint16(h[2:4], uint16(length-1)) }
func (h headerV20) IsFinal() bool         { return h[4]&0x80 == 0x80 }
func (h headerV20) Nonce() []byte         { return h[4:headerSize] }
func (h headerV20) AddData() []byte       { return h[:4] }
func (h headerV20) SetRand(randVal []byte, final bool) {
    copy(h[4:], randVal)
    if final {
        h[4] |= 0x80
    } else {
        h[4] &= 0x7F
    }
}
     */

    public ref struct DareHeaderV20
    {
        private readonly Span<byte> _h;

        public static DareHeaderV20 Create()
        {
            return new DareHeaderV20(new byte[Dare20.HeaderSize]);
        }

        public DareHeaderV20(Span<byte> h)
        {
            if (h.Length != Dare20.HeaderSize)
            {
                throw new InvalidOperationException("Invalid header length!");
            }

            _h = h;
        }

        public ReadOnlySpan<byte> Buffer => _h;

        public byte Version => _h[0];

        public void SetVersion() { _h[0] = Dare20.Version; }

        public byte Cipher => _h[1];

        public void SetCipher() { _h[1] = Dare20.CipherSuiteAes256Gcm; }

        public int Length => BitConverter.ToUInt16(_h.Slice(start: 2, length: 2)) + 1;

        public void SetLength(int length) { BitConverter.GetBytes((ushort)(length - 1)).CopyTo(_h.Slice(start: 2, length: 2)); }

        public bool IsFinal => (_h[4] & 0x80) == 0x80;

        public Span<byte> Nonce => _h.Slice(start: 4, length: 12);

        public Span<byte> AddData => _h.Slice(start: 0, length: 4);

        public void SetRand(byte[] randVal, bool final)
        {
            randVal.CopyTo(_h.Slice(start: 4, length: 12));

            if (final)
            {
                _h[4] |= 0x80;
            }
            else
            {
                _h[4] &= 0x7F;
            }
        }
    }
}
#pragma warning restore SA1201 // Elements must appear in the correct order
#pragma warning restore SA1502 // Element must not be on a single line
#pragma warning restore SA1206 // Declaration keywords must follow order

