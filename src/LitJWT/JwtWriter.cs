using System;
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace LitJWT
{
    public readonly struct JwtWriter
    {
        static byte[] dot = Encoding.UTF8.GetBytes(".");
        static byte[] expKey = Encoding.UTF8.GetBytes(@"""exp"":");
        static byte[] expKeyWithComma = Encoding.UTF8.GetBytes(@",""exp"":");

        readonly IBufferWriter<byte> writer;
        readonly IJwtAlgorithm algorithm;
        readonly long? expire;

        internal readonly JsonSerializerOptions serializerOptions;

        public JwtWriter(IBufferWriter<byte> writer, IJwtAlgorithm algorithm, DateTimeOffset? expire)
            : this(writer, algorithm, expire, null)
        {
        }

        internal JwtWriter(IBufferWriter<byte> writer, IJwtAlgorithm algorithm, DateTimeOffset? expire, JsonSerializerOptions serializerOptions)
        {
            this.writer = writer;
            this.algorithm = algorithm;
            if (expire != null)
            {
                this.expire = expire.Value.ToUnixTimeSeconds();
            }
            else
            {
                this.expire = null;
            }
            this.serializerOptions = serializerOptions;
        }

        public void Write(ReadOnlySpan<byte> payload)
        {
            // to avoid payload copy, write all data in this place.
            // make new payload....

            byte[] newPayloadArray = null;
            try
            {
                if (expire != null)
                {
                    newPayloadArray = ArrayPool<byte>.Shared.Rent(payload.Length + 8 + 20); // ,"exp":} + maxint-size
                    var newPayload = newPayloadArray.AsSpan();

                    payload.CopyTo(newPayload);
                    newPayload = newPayload.Slice(payload.Length - 1); // except }
                    int expLength;
                    if (payload.Length == 0 || payload.Length == 2) // {}
                    {
                        expKey.CopyTo(newPayload);
                        newPayload = newPayload.Slice(expKey.Length);
                        expLength = expKey.Length;
                    }
                    else
                    {
                        expKeyWithComma.CopyTo(newPayload);
                        newPayload = newPayload.Slice(expKeyWithComma.Length);
                        expLength = expKeyWithComma.Length;
                    }

                    var writeLength = NumberConverter.WriteInt64(newPayload, 0, expire.Value);
                    newPayload = newPayload.Slice(writeLength);
                    newPayload[0] = (byte)'}';

                    payload = newPayloadArray.AsSpan(0, payload.Length + writeLength + expLength);
                }

                var headerBase64 = algorithm.HeaderBase64Url;
                byte[] rentByte = null;
                var payloadEncodedLength = Base64.GetBase64UrlEncodeLength(payload.Length);
                if (payloadEncodedLength > 1024)
                {
                    rentByte = ArrayPool<byte>.Shared.Rent(payloadEncodedLength);
                }
                try
                {
                    Span<byte> payloadBase64 = (rentByte != null)
                        ? rentByte.AsSpan(0, payloadEncodedLength)
                        : stackalloc byte[payloadEncodedLength];
                    Base64.TryToBase64UrlUtf8(payload, payloadBase64, out _);

                    // We can compute final size, so GetSpan only once.
                    // hedaer . payload . signature
                    var length = headerBase64.Length + payloadBase64.Length + 2 + Base64.GetBase64UrlEncodeLength(algorithm.HashSize);
                    var finalBuffer = writer.GetSpan(length);

                    headerBase64.CopyTo(finalBuffer);
                    dot.CopyTo(finalBuffer.Slice(headerBase64.Length));
                    payloadBase64.CopyTo(finalBuffer.Slice(headerBase64.Length + 1));
                    dot.CopyTo(finalBuffer.Slice(headerBase64.Length + 1 + payloadBase64.Length));

                    Span<byte> signature = stackalloc byte[algorithm.HashSize];
                    algorithm.Sign(finalBuffer.Slice(0, headerBase64.Length + 1 + payloadBase64.Length), signature);

                    Base64.TryToBase64UrlUtf8(signature, finalBuffer.Slice(headerBase64.Length + 2 + payloadBase64.Length), out _);

                    writer.Advance(length);
                }
                finally
                {
                    if (rentByte != null)
                    {
                        ArrayPool<byte>.Shared.Return(rentByte);
                    }
                }
            }
            finally
            {
                if (newPayloadArray != null)
                {
                    ArrayPool<byte>.Shared.Return(newPayloadArray);
                }
            }
        }
    }
}
