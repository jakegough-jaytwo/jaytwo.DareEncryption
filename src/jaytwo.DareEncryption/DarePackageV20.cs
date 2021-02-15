#pragma warning disable SA1201 // Elements must appear in the correct order
#pragma warning disable SA1502 // Element must not be on a single line
#pragma warning disable SA1206 // Declaration keywords must follow order

using System;
using System.Collections.Generic;
using System.Text;

namespace jaytwo.DareEncryption
{
    // port of https://github.com/minio/sio/blob/6a41828a60f0ec95a159ce7921ca3dd566ebd7e3/dare.go#L65-L70

    /*
type packageV20 []byte

func (p packageV20) Header() headerV20  { return headerV20(p[:headerSize]) }
func (p packageV20) Payload() []byte    { return p[headerSize : headerSize+p.Header().Length()] }
func (p packageV20) Ciphertext() []byte { return p[headerSize:p.Length()] }
func (p packageV20) Length() int        { return headerSize + tagSize + p.Header().Length() }
     */

    public ref struct DarePackageV20
    {
        private readonly Span<byte> _p;

        public DarePackageV20(Span<byte> p)
        {
            if (p.Length > Dare20.MaxPackageLength)
            {
                throw new InvalidOperationException("Package too long!");
            }

            if (p.Length < Dare20.MinPackageLength)
            {
                throw new InvalidOperationException("Package too short!");
            }

            _p = p;
        }

        public ReadOnlySpan<byte> Buffer => _p;

        public DareHeaderV20 Header => new DareHeaderV20(_p.Slice(start: 0, length: Dare20.HeaderSize));

        public ReadOnlySpan<byte> Payload => _p.Slice(start: Dare20.HeaderSize, length: Header.Length);

        public ReadOnlySpan<byte> Ciphertext => _p.Slice(start: Dare20.HeaderSize, length: Header.Length + Dare20.TagSize);

        public int Length => Dare20.HeaderSize + Dare20.TagSize + Header.Length;
    }
}

#pragma warning restore SA1201 // Elements must appear in the correct order
#pragma warning restore SA1502 // Element must not be on a single line
#pragma warning restore SA1206 // Declaration keywords must follow order
