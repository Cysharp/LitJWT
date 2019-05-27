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

        public string Encode<T>(T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            return Encode<T>(payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public string Encode<T>(T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = new Utf8BufferWriter();
            var writer = new JwtWriter(buffer, signAlgorithm, expire);
            payloadWriter(payload, writer);
            return buffer.ToString();
        }

        public byte[] EncodeAsUtf8Bytes<T>(T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            return EncodeAsUtf8Bytes<T>(payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public byte[] EncodeAsUtf8Bytes<T>(T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = new Utf8BufferWriter();
            var writer = new JwtWriter(buffer, signAlgorithm, expire);
            payloadWriter(payload, writer);
            return buffer.ToUtf8Bytes();
        }

        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            Encode<T>(bufferWriter, payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var writer = new JwtWriter(bufferWriter, signAlgorithm, expire);
            payloadWriter(payload, writer);
        }
    }
}
