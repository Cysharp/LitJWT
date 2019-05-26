using System;
using System.Buffers;
using System.Text;
using Utf8Json;

namespace LitJWT
{
    public delegate T PayloadParser<T>(ReadOnlySpan<byte> payload);

    public class JwtDecoder
    {
        readonly IJwtAlgorithmResolver resolver;

        public JwtDecoder(params IJwtAlgorithm[] algorithms)
            : this(new JwtAlgorithmResolver(algorithms))
        {
        }

        public JwtDecoder(IJwtAlgorithmResolver resolver)
        {
            this.resolver = resolver;
        }

        void Split(string text, out ReadOnlySpan<char> header, out ReadOnlySpan<char> payload, out ReadOnlySpan<char> headerAndPayload, out ReadOnlySpan<char> signature)
        {
            header = default;
            payload = default;
            signature = default;
            headerAndPayload = default;

            var foundHeader = false;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == '.')
                {
                    if (!foundHeader)
                    {
                        header = text.AsSpan(0, i);
                        foundHeader = true;
                    }
                    else
                    {
                        var offset = header.Length + 1;
                        payload = text.AsSpan(offset, i - offset);
                        headerAndPayload = text.AsSpan(0, offset + i - offset);
                        signature = text.AsSpan(i + 1, text.Length - (i + 1));
                        break;
                    }
                }
            }
        }

        void Split(ReadOnlySpan<byte> text, out ReadOnlySpan<byte> header, out ReadOnlySpan<byte> payload, out ReadOnlySpan<byte> headerAndPayload, out ReadOnlySpan<byte> signature)
        {
            header = default;
            payload = default;
            signature = default;
            headerAndPayload = default;

            var foundHeader = false;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == (byte)'.')
                {
                    if (!foundHeader)
                    {
                        header = text.Slice(0, i);
                        foundHeader = true;
                    }
                    else
                    {
                        var offset = header.Length + 1;
                        payload = text.Slice(offset, i - offset);
                        headerAndPayload = text.Slice(0, i - offset);
                        signature = text.Slice(i + 1, text.Length - (i + 1));
                        break;
                    }
                }
            }
        }

        // TODO:
        // public bool TryDecode<T>(ReadOnlySpan<byte> token, PayloadParser<T> payloadParser, out T payloadResult)

        // TODO: return DecodeResult
        public bool TryDecode<T>(string token, PayloadParser<T> payloadParser, out T payloadResult)
        {
            Split(token, out var header, out var payload, out var headerAndPayload, out var signature);

            IJwtAlgorithm algorithm = null;

            // parsing header.
            {
                Span<byte> bytes = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(header.Length)];
                if (!Base64.TryFromBase64UrlChars(header, bytes, out var bytesWritten))
                {
                    throw new InvalidOperationException("Invalid Token");
                }

                var reader = new JsonReader(bytes.Slice(0, bytesWritten));
                var count = 0;
                while (reader.ReadIsInObject(ref count))
                {
                    // try to read algorithm span.
                    if (reader.ReadPropertyNameSegmentRaw().SequenceEqual(JwtConstantsUtf8.Algorithm))
                    {
                        algorithm = resolver.Resolve(reader.ReadStringSegmentRaw());
                    }
                    else
                    {
                        reader.ReadNextBlock();
                    }
                }
            }

            // parsing payload.
            int? expiry;
            {
                // TODO:get from arraypool?
                Span<byte> bytes = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(payload.Length)];
                if (!Base64.TryFromBase64UrlChars(header, bytes, out var bytesWritten))
                {
                    throw new InvalidOperationException("Invalid Token");
                }

                var decodedPayload = bytes.Slice(0, bytesWritten);

                var reader = new JsonReader(decodedPayload);
                var count = 0;
                while (reader.ReadIsInObject(ref count))
                {
                    // try to read algorithm span.
                    if (reader.ReadPropertyNameSegmentRaw().SequenceEqual(JwtConstantsUtf8.Expiration))
                    {
                        expiry = reader.ReadInt32();
                    }
                    else
                    {
                        reader.ReadNextBlock();
                    }
                }

                // and custom deserialize.
                payloadResult = payloadParser(decodedPayload);
            }

            // parsing signature.
            {
                if (algorithm == null)
                {
                    throw new Exception(""); // invalid
                }

                var rentBuffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(headerAndPayload.Length));
                try
                {
                    Span<byte> signatureDecoded = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(signature.Length)];
                    if (!Base64.TryFromBase64UrlChars(signature, signatureDecoded, out var bytesSritten))
                    {
                        throw new Exception(); // invalid
                    }

                    var signBuffer = rentBuffer.AsSpan();
                    var byteCount = Encoding.UTF8.GetBytes(headerAndPayload, signBuffer);
                    signBuffer = signBuffer.Slice(0, byteCount);
                    Span<byte> signatureDest = stackalloc byte[algorithm.HashSize];
                    algorithm.Sign(signBuffer, signatureDest);

                    if (!signatureDest.SequenceEqual(signatureDecoded.Slice(0, bytesSritten)))
                    {
                        throw new Exception(); // invalid
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rentBuffer);
                }
            }

            // all ok
            return true;
        }
    }
}