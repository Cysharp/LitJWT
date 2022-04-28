using System;
using System.Buffers;
using System.Text.Json;

namespace LitJWT
{
    public class JwtEncoder
    {
        readonly IJwtAlgorithm signAlgorithm;
        readonly JsonSerializerOptions serializerOptions;

        [ThreadStatic]
        static Utf8BufferWriter encodeWriter = null;

        public IJwtAlgorithm SignAlgorithm => signAlgorithm;


        static Utf8BufferWriter GetWriter()
        {
            if (encodeWriter == null)
            {
                encodeWriter = new Utf8BufferWriter();
            }
            return encodeWriter;
        }

        public JwtEncoder(IJwtAlgorithm signAlgorithm)
        {
            this.signAlgorithm = signAlgorithm;
            this.serializerOptions = null;
        }

        public JwtEncoder(IJwtAlgorithm signAlgorithm, JsonSerializerOptions serializerOptions)
        {
            this.signAlgorithm = signAlgorithm;
            this.serializerOptions = serializerOptions;
        }

        public string Encode<T>(T payload, TimeSpan expire) => Encode(payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));
        public string Encode<T>(T payload, DateTimeOffset? expire) => Encode(payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));
        public byte[] EncodeAsUtf8Bytes<T>(T payload, TimeSpan expire) => EncodeAsUtf8Bytes(payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));
        public byte[] EncodeAsUtf8Bytes<T>(T payload, DateTimeOffset? expire) => EncodeAsUtf8Bytes(payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));
        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, TimeSpan expire) => Encode(bufferWriter, payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));
        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, DateTimeOffset? expire) => Encode(bufferWriter, payload, expire, static (x, writer) => writer.Write(JsonSerializer.SerializeToUtf8Bytes(x, writer.serializerOptions)));

        public string Encode<T>(T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            return Encode<T>(payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public string Encode<T>(T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = GetWriter();
            try
            {
                var writer = new JwtWriter(buffer, signAlgorithm, expire, serializerOptions);
                payloadWriter(payload, writer);
                return buffer.ToString();
            }
            finally
            {
                buffer.Reset();
            }
        }

        public byte[] EncodeAsUtf8Bytes<T>(T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            return EncodeAsUtf8Bytes<T>(payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public byte[] EncodeAsUtf8Bytes<T>(T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var buffer = GetWriter();
            try
            {
                var writer = new JwtWriter(buffer, signAlgorithm, expire, serializerOptions);
                payloadWriter(payload, writer);
                return buffer.ToUtf8Bytes();
            }
            finally
            {
                buffer.Reset();
            }
        }

        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, TimeSpan expire, Action<T, JwtWriter> payloadWriter)
        {
            Encode<T>(bufferWriter, payload, DateTimeOffset.UtcNow.Add(expire), payloadWriter);
        }

        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, DateTimeOffset? expire, Action<T, JwtWriter> payloadWriter)
        {
            var writer = new JwtWriter(bufferWriter, signAlgorithm, expire, serializerOptions);
            payloadWriter(payload, writer);
        }
    }
}
