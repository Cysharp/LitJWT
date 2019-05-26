using System;
using System.Buffers;
using System.Text;

namespace LitJWT
{
    public readonly struct JwtWriter
    {
        static byte[] dot = Encoding.UTF8.GetBytes(".");

        readonly IBufferWriter<byte> writer;
        readonly IJwtAlgorithm algorithm;

        public JwtWriter(IBufferWriter<byte> writer, IJwtAlgorithm algorithm)
        {
            this.writer = writer;
            this.algorithm = algorithm;
        }

        public void Write(ReadOnlySpan<byte> payload)
        {
            // to avoid payload copy, write all data in this place.

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
                Base64.TryEncodeBase64Url(payload, payloadBase64, out _);

                // We can compute final size, so GetSpan only once.
                // hedaer . payload . signature
                var finalBuffer = writer.GetSpan(headerBase64.Length + payloadBase64.Length + 2 + Base64.GetBase64UrlEncodeLength(algorithm.HashSize));

                headerBase64.CopyTo(finalBuffer);
                dot.CopyTo(finalBuffer.Slice(headerBase64.Length));
                payloadBase64.CopyTo(finalBuffer.Slice(headerBase64.Length + 1));
                dot.CopyTo(finalBuffer.Slice(headerBase64.Length + 1 + payloadBase64.Length));

                Span<byte> signature = stackalloc byte[algorithm.HashSize];
                var foo = finalBuffer.Slice(0, headerBase64.Length + 1 + payloadBase64.Length);
                algorithm.Sign(finalBuffer.Slice(0, headerBase64.Length + 1 + payloadBase64.Length), signature);

                Base64.TryEncodeBase64Url(signature, finalBuffer.Slice(headerBase64.Length + 2 + payloadBase64.Length), out _);

                // TODO:requires advance operation to writer?
            }
            finally
            {
                if (rentByte != null)
                {
                    ArrayPool<byte>.Shared.Return(rentByte);
                }
            }
        }
    }
}
