using System;
using System.Buffers;

namespace LitJWT
{
    public class JwtEncoder
    {
        IJwtAlgorithm signAlgorithm;

        public JwtEncoder(IJwtAlgorithm signAlgorithm)
        {
            this.signAlgorithm = signAlgorithm;
        }

        public string Encode<T>(T payload, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = new Utf8BufferWriter();
            var writer = new JwtWriter(buffer, signAlgorithm);
            payloadWriter(payload, writer);
            return buffer.ToString();
        }

        public byte[] EncodeAsUtf8Bytes<T>(T payload, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = new Utf8BufferWriter();
            var writer = new JwtWriter(buffer, signAlgorithm);
            payloadWriter(payload, writer);
            return buffer.ToUtf8Bytes();
        }

        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, Action<T, JwtWriter> payloadWriter)
        {
            var writer = new JwtWriter(bufferWriter, signAlgorithm);
            payloadWriter(payload, writer);
        }
    }
}
