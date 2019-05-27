using System;
using System.Buffers;
using System.Text;
using Utf8Json;

namespace LitJWT
{
    public delegate T PayloadParser<T>(ReadOnlySpan<byte> payload);

    public enum DecodeResult
    {
        Success,
        InvalidBase64UrlHeader,
        InvalidBase64UrlPayload,
        InvalidBase64UrlSignature,
        AlgorithmNotExists,
        FailedVerifySignature,
        FailedVerifyExpire,
        FailedVerifyNotBefore,
    }

    public class JwtDecoder
    {
        readonly JwtAlgorithmResolver resolver;

        public JwtDecoder(params IJwtAlgorithm[] algorithms)
            : this(new JwtAlgorithmResolver(algorithms))
        {
        }

        public JwtDecoder(JwtAlgorithmResolver resolver)
        {
            this.resolver = resolver;
        }

        static void Split(ReadOnlySpan<char> text, out ReadOnlySpan<char> header, out ReadOnlySpan<char> payload, out ReadOnlySpan<char> headerAndPayload, out ReadOnlySpan<char> signature)
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
                        header = text.Slice(0, i);
                        foundHeader = true;
                    }
                    else
                    {
                        var offset = header.Length + 1;
                        payload = text.Slice(offset, i - offset);
                        headerAndPayload = text.Slice(0, offset + i - offset);
                        signature = text.Slice(i + 1, text.Length - (i + 1));
                        break;
                    }
                }
            }
        }

        static void Split(ReadOnlySpan<byte> text, out ReadOnlySpan<byte> header, out ReadOnlySpan<byte> payload, out ReadOnlySpan<byte> headerAndPayload, out ReadOnlySpan<byte> signature)
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
                        headerAndPayload = text.Slice(0, offset + i - offset);
                        signature = text.Slice(i + 1, text.Length - (i + 1));
                        break;
                    }
                }
            }
        }

        public string GetPayloadJson(string token)
        {
            return GetPayloadJson(token.AsSpan());
        }

        public string GetPayloadJson(ReadOnlySpan<char> token)
        {
            Split(token, out var header, out var payload, out var headerAndPayload, out var signature);
            var rentBytes = ArrayPool<byte>.Shared.Rent(Base64.GetMaxBase64UrlDecodeLength(payload.Length));
            try
            {
                Span<byte> bytes = rentBytes.AsSpan();
                if (!Base64.TryFromBase64UrlChars(payload, bytes, out var bytesWritten))
                {
                    throw new InvalidOperationException("Fail to decode base64url, payload:" + new string(payload));
                }
                return Encoding.UTF8.GetString(bytes.Slice(0, bytesWritten));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rentBytes);
            }
        }

        public string GetPayloadJson(ReadOnlySpan<byte> utf8token)
        {
            Split(utf8token, out var header, out var payload, out var headerAndPayload, out var signature);
            var rentBytes = ArrayPool<byte>.Shared.Rent(Base64.GetMaxBase64UrlDecodeLength(payload.Length));
            try
            {
                Span<byte> bytes = rentBytes.AsSpan();
                if (!Base64.TryFromBase64UrlUtf8(payload, bytes, out var bytesWritten))
                {
                    throw new InvalidOperationException("Fail to decode base64url, payload:" + Encoding.UTF8.GetString(payload));
                }
                return Encoding.UTF8.GetString(bytes.Slice(0, bytesWritten));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rentBytes);
            }
        }

        public DecodeResult TryDecode<T>(ReadOnlySpan<byte> utf8token, PayloadParser<T> payloadParser, out T payloadResult)
        {
            Split(utf8token, out var header, out var payload, out var headerAndPayload, out var signature);

            IJwtAlgorithm algorithm = null;

            // parsing header.
            {
                // first, try quick match
                algorithm = resolver.ResolveFromBase64Header(header);
                if (algorithm == null)
                {
                    Span<byte> bytes = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(header.Length)];
                    if (!Base64.TryFromBase64UrlUtf8(header, bytes, out var bytesWritten))
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidBase64UrlHeader;
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
            }

            // parsing payload.
            long? expiry = null;
            long? notBefore = null;
            {
                var rentBytes = ArrayPool<byte>.Shared.Rent(Base64.GetMaxBase64UrlDecodeLength(payload.Length));
                try
                {
                    Span<byte> bytes = rentBytes.AsSpan();
                    if (!Base64.TryFromBase64UrlUtf8(payload, bytes, out var bytesWritten))
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidBase64UrlPayload;
                    }

                    var decodedPayload = bytes.Slice(0, bytesWritten);

                    var reader = new JsonReader(decodedPayload);
                    var count = 0;
                    while (reader.ReadIsInObject(ref count))
                    {
                        // try to read algorithm span.
                        var rawSegment = reader.ReadPropertyNameSegmentRaw();
                        if (rawSegment.SequenceEqual(JwtConstantsUtf8.Expiration))
                        {
                            expiry = reader.ReadInt64();
                        }
                        else if (rawSegment.SequenceEqual(JwtConstantsUtf8.NotBefore))
                        {
                            notBefore = reader.ReadInt64();
                        }
                        else
                        {
                            reader.ReadNextBlock();
                        }
                    }

                    // and custom deserialize.
                    payloadResult = payloadParser(decodedPayload);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rentBytes);
                }
            }
            if (expiry != null)
            {
                var expireTime = DateTimeOffset.FromUnixTimeSeconds(expiry.Value);
                if (expireTime - DateTimeOffset.UtcNow < TimeSpan.Zero)
                {
                    return DecodeResult.FailedVerifyExpire;
                }
            }
            if (notBefore != null)
            {
                var notBeforeTime = DateTimeOffset.FromUnixTimeSeconds(notBefore.Value);
                if (DateTimeOffset.UtcNow - notBeforeTime < TimeSpan.Zero)
                {
                    return DecodeResult.FailedVerifyNotBefore;
                }
            }

            // parsing signature.
            {
                if (algorithm == null)
                {
                    return DecodeResult.AlgorithmNotExists;
                }

                Span<byte> signatureDecoded = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(signature.Length)];
                if (!Base64.TryFromBase64UrlUtf8(signature, signatureDecoded, out var bytesWritten))
                {
                    return DecodeResult.InvalidBase64UrlSignature;
                }
                signatureDecoded = signatureDecoded.Slice(0, bytesWritten);

                if (!algorithm.Verify(headerAndPayload, signatureDecoded))
                {
                    return DecodeResult.FailedVerifySignature;
                }
            }

            // all ok
            return DecodeResult.Success;
        }

        public DecodeResult TryDecode<T>(string token, PayloadParser<T> payloadParser, out T payloadResult)
        {
            return TryDecode<T>(token.AsSpan(), payloadParser, out payloadResult);
        }

        public DecodeResult TryDecode<T>(ReadOnlySpan<char> token, PayloadParser<T> payloadParser, out T payloadResult)
        {
            Split(token, out var header, out var payload, out var headerAndPayload, out var signature);

            IJwtAlgorithm algorithm = null;

            // parsing header.
            {
                Span<byte> bytes = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(header.Length)];
                if (!Base64.TryFromBase64UrlChars(header, bytes, out var bytesWritten))
                {
                    payloadResult = default;
                    return DecodeResult.InvalidBase64UrlHeader;
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
            long? expiry = null;
            long? notBefore = null;
            {
                var rentBytes = ArrayPool<byte>.Shared.Rent(Base64.GetMaxBase64UrlDecodeLength(payload.Length));
                try
                {
                    Span<byte> bytes = rentBytes.AsSpan();
                    if (!Base64.TryFromBase64UrlChars(payload, bytes, out var bytesWritten))
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidBase64UrlPayload;
                    }

                    var decodedPayload = bytes.Slice(0, bytesWritten);

                    var reader = new JsonReader(decodedPayload);
                    var count = 0;
                    while (reader.ReadIsInObject(ref count))
                    {
                        // try to read algorithm span.
                        var rawSegment = reader.ReadPropertyNameSegmentRaw();
                        if (rawSegment.SequenceEqual(JwtConstantsUtf8.Expiration))
                        {
                            expiry = reader.ReadInt64();
                        }
                        else if (rawSegment.SequenceEqual(JwtConstantsUtf8.NotBefore))
                        {
                            notBefore = reader.ReadInt64();
                        }
                        else
                        {
                            reader.ReadNextBlock();
                        }
                    }

                    // and custom deserialize.
                    payloadResult = payloadParser(decodedPayload);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rentBytes);
                }
            }
            if (expiry != null)
            {
                var now = DateTimeOffset.UtcNow;
                var expireTime = DateTimeOffset.FromUnixTimeSeconds(expiry.Value);
                if (expireTime - now < TimeSpan.Zero)
                {
                    return DecodeResult.FailedVerifyExpire;
                }
            }
            if (notBefore != null)
            {
                var now = DateTimeOffset.UtcNow;
                var notBeforeTime = DateTimeOffset.FromUnixTimeSeconds(notBefore.Value);
                if (now - notBeforeTime < TimeSpan.Zero)
                {
                    return DecodeResult.FailedVerifyNotBefore;
                }
            }

            // parsing signature.
            {
                if (algorithm == null)
                {
                    return DecodeResult.AlgorithmNotExists;
                }

                var rentBuffer = ArrayPool<byte>.Shared.Rent(Encoding.UTF8.GetMaxByteCount(headerAndPayload.Length));
                try
                {
                    Span<byte> signatureDecoded = stackalloc byte[Base64.GetMaxBase64UrlDecodeLength(signature.Length)];
                    if (!Base64.TryFromBase64UrlChars(signature, signatureDecoded, out var bytesWritten))
                    {
                        return DecodeResult.InvalidBase64UrlSignature;
                    }
                    signatureDecoded = signatureDecoded.Slice(0, bytesWritten);

                    var signBuffer = rentBuffer.AsSpan();
                    var byteCount = Encoding.UTF8.GetBytes(headerAndPayload, signBuffer);
                    signBuffer = signBuffer.Slice(0, byteCount);
                    if (!algorithm.Verify(signBuffer, signatureDecoded))
                    {
                        return DecodeResult.FailedVerifySignature;
                    }
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rentBuffer);
                }
            }

            // all ok
            return DecodeResult.Success;
        }
    }
}