using System;
using System.Buffers;
using System.Text;
using System.Text.Json;

namespace LitJWT
{
    public delegate T PayloadParser<T>(ReadOnlySpan<byte> payload);
    internal delegate T InternalPayloadParser<T>(ReadOnlySpan<byte> payload, JsonSerializerOptions serializerOptions);

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
        InvalidHeaderFormat,
        InvalidPayloadFormat,
    }

    public class JwtDecoder
    {
        readonly JwtAlgorithmResolver resolver;
        readonly JsonSerializerOptions serializerOptions;

        public JwtDecoder(params IJwtAlgorithm[] algorithms)
            : this(new JwtAlgorithmResolver(algorithms))
        {
        }
        public JwtDecoder(IJwtAlgorithm[] algorithms, JsonSerializerOptions serializerOptions)
            : this(new JwtAlgorithmResolver(algorithms), serializerOptions)
        {
        }


        public JwtDecoder(JwtAlgorithmResolver resolver)
            : this(resolver, null)
        {
        }

        public JwtDecoder(JwtAlgorithmResolver resolver, JsonSerializerOptions serializerOptions)
        {
            this.resolver = resolver;
            this.serializerOptions = serializerOptions;
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

        public DecodeResult TryDecode<T>(ReadOnlySpan<byte> utf8token, out T payloadResult) => TryDecodeCore(utf8token, static (x, options) => JsonSerializer.Deserialize<T>(x, options), out payloadResult);
        public DecodeResult TryDecode<T>(string token, out T payloadResult) => TryDecodeCore(token.AsSpan(), static (x, options) => JsonSerializer.Deserialize<T>(x, options), out payloadResult);
        public DecodeResult TryDecode<T>(ReadOnlySpan<char> token, out T payloadResult) => TryDecodeCore(token, static (x, options) => JsonSerializer.Deserialize<T>(x, options), out payloadResult);

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

                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(bytes.Slice(0, bytesWritten));
                        while (reader.Read())
                        {
                            if (reader.TokenType == JsonTokenType.EndObject) break;

                            // try to read algorithm span.
                            if (reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals(JwtConstantsUtf8.Algorithm))
                            {
                                reader.Read();
                                algorithm = resolver.Resolve(reader.ValueSpan);
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidHeaderFormat;
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
                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                        while (reader.Read())
                        {
                            if (reader.CurrentDepth == 1 && reader.TokenType == JsonTokenType.PropertyName)
                            {
                                if (reader.ValueTextEquals(JwtConstantsUtf8.Expiration))
                                {
                                    reader.Read();
                                    expiry = reader.GetInt64();
                                }
                                else if (reader.ValueTextEquals(JwtConstantsUtf8.NotBefore))
                                {
                                    reader.Read();
                                    notBefore = reader.GetInt64();
                                }
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidPayloadFormat;
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

                var decodedPayload = bytes.Slice(0, bytesWritten);
                try
                {
                    var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                    while (reader.Read())
                    {
                        if (reader.TokenType == System.Text.Json.JsonTokenType.EndObject) break;

                        // try to read algorithm span.
                        if (reader.TokenType == JsonTokenType.PropertyName)
                        {
                            if (reader.ValueTextEquals(JwtConstantsUtf8.Algorithm))
                            {
                                if (!reader.Read())
                                {
                                    payloadResult = default;
                                    return DecodeResult.InvalidHeaderFormat;
                                }
                                algorithm = resolver.Resolve(reader.ValueSpan);
                            }
                        }
                    }
                }
                catch (JsonException)
                {
                    payloadResult = default;
                    return DecodeResult.InvalidHeaderFormat;
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

                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                        while (reader.Read())
                        {
                            if (reader.CurrentDepth == 1 && reader.TokenType == JsonTokenType.PropertyName)
                            {
                                if (reader.ValueTextEquals(JwtConstantsUtf8.Expiration))
                                {
                                    if (!reader.Read())
                                    {
                                        payloadResult = default;
                                        return DecodeResult.InvalidHeaderFormat;
                                    }
                                    expiry = reader.GetInt64();
                                }
                                else if (reader.ValueTextEquals(JwtConstantsUtf8.NotBefore))
                                {
                                    if (!reader.Read())
                                    {
                                        payloadResult = default;
                                        return DecodeResult.InvalidHeaderFormat;
                                    }
                                    notBefore = reader.GetInt64();
                                }
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidHeaderFormat;
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

        // note:ugly copy and paste code...
        DecodeResult TryDecodeCore<T>(ReadOnlySpan<byte> utf8token, InternalPayloadParser<T> payloadParser, out T payloadResult)
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

                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(bytes.Slice(0, bytesWritten));
                        while (reader.Read())
                        {
                            if (reader.TokenType == JsonTokenType.EndObject) break;

                            // try to read algorithm span.
                            if (reader.TokenType == JsonTokenType.PropertyName && reader.ValueTextEquals(JwtConstantsUtf8.Algorithm))
                            {
                                reader.Read();
                                algorithm = resolver.Resolve(reader.ValueSpan);
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidHeaderFormat;
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
                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                        while (reader.Read())
                        {
                            if (reader.CurrentDepth == 1 && reader.TokenType == JsonTokenType.PropertyName)
                            {
                                if (reader.ValueTextEquals(JwtConstantsUtf8.Expiration))
                                {
                                    reader.Read();
                                    expiry = reader.GetInt64();
                                }
                                else if (reader.ValueTextEquals(JwtConstantsUtf8.NotBefore))
                                {
                                    reader.Read();
                                    notBefore = reader.GetInt64();
                                }
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidPayloadFormat;
                    }

                    // and custom deserialize.
                    payloadResult = payloadParser(decodedPayload, serializerOptions);
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

        DecodeResult TryDecodeCore<T>(ReadOnlySpan<char> token, InternalPayloadParser<T> payloadParser, out T payloadResult)
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

                var decodedPayload = bytes.Slice(0, bytesWritten);
                try
                {
                    var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                    while (reader.Read())
                    {
                        if (reader.TokenType == System.Text.Json.JsonTokenType.EndObject) break;

                        // try to read algorithm span.
                        if (reader.TokenType == JsonTokenType.PropertyName)
                        {
                            if (reader.ValueTextEquals(JwtConstantsUtf8.Algorithm))
                            {
                                if (!reader.Read())
                                {
                                    payloadResult = default;
                                    return DecodeResult.InvalidHeaderFormat;
                                }
                                algorithm = resolver.Resolve(reader.ValueSpan);
                            }
                        }
                    }
                }
                catch (JsonException)
                {
                    payloadResult = default;
                    return DecodeResult.InvalidHeaderFormat;
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

                    try
                    {
                        var reader = new System.Text.Json.Utf8JsonReader(decodedPayload);
                        while (reader.Read())
                        {
                            if (reader.CurrentDepth == 1 && reader.TokenType == JsonTokenType.PropertyName)
                            {
                                if (reader.ValueTextEquals(JwtConstantsUtf8.Expiration))
                                {
                                    if (!reader.Read())
                                    {
                                        payloadResult = default;
                                        return DecodeResult.InvalidHeaderFormat;
                                    }
                                    expiry = reader.GetInt64();
                                }
                                else if (reader.ValueTextEquals(JwtConstantsUtf8.NotBefore))
                                {
                                    if (!reader.Read())
                                    {
                                        payloadResult = default;
                                        return DecodeResult.InvalidHeaderFormat;
                                    }
                                    notBefore = reader.GetInt64();
                                }
                            }
                        }
                    }
                    catch (JsonException)
                    {
                        payloadResult = default;
                        return DecodeResult.InvalidPayloadFormat;
                    }

                    // and custom deserialize.
                    payloadResult = payloadParser(decodedPayload, serializerOptions);
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