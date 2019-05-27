using System;
using System.Buffers;
using System.Text;

namespace LitJWT
{
    internal class Utf8BufferWriter : IBufferWriter<byte>
    {
        int size;
        byte[] underlyingBuffer;

        public void Advance(int count)
        {
            // do nothing
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            throw new NotImplementedException();
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            if (underlyingBuffer == null)
            {
                size = sizeHint;
                underlyingBuffer = ArrayPool<byte>.Shared.Rent(sizeHint);
            }
            return underlyingBuffer;
        }

        public byte[] ToUtf8Bytes()
        {
            var finalBuffer = new byte[size];
            Array.Copy(underlyingBuffer, 0, finalBuffer, 0, size);
            return finalBuffer;
        }

        public override string ToString()
        {
            return Encoding.UTF8.GetString(underlyingBuffer, 0, size);
        }

        public void Reset()
        {
            size = 0;
            if (underlyingBuffer != null) ArrayPool<byte>.Shared.Return(underlyingBuffer);
            underlyingBuffer = null;
        }
    }
}
