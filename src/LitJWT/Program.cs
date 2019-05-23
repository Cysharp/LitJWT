using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LitJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }
    }




    public static class Jwt
    {
        public static void Encode()
        {
        }
    }


    public class DefaultDecoder
    {
        (StringSegment header, StringSegment payload, StringSegment signature) Split(string text)
        {
            StringSegment header = default;
            StringSegment payload = default;
            StringSegment signature = default;

            var foundHeader = false;
            for (int i = 0; i < text.Length; i++)
            {
                if (text[i] == '.')
                {
                    if (!foundHeader)
                    {
                        header = new StringSegment(text, 0, i);
                        foundHeader = true;
                    }
                    else
                    {
                        var offset = header.Count + 1;
                        payload = new StringSegment(text, offset, i - offset);
                        signature = new StringSegment(text, i + 1, text.Length - (i + 1));
                        break;
                    }
                }
            }

            return (header, payload, signature);
        }

        public delegate T PayloadParser<T>(ReadOnlySpan<char> payload);


        public void Encode<T>(IBufferWriter<byte> bufferWriter, T payload, IJwtAlgorithm algorithm)
        {
            bufferWriter.Write(algorithm.HeaderBase64WithDot);
            // write payload.

            // algorithm.



            // bufferWriter.Write(".");



            // IJwtAlgorithmResolver foo;

            // new Utf8JsonWriter(

        }



        // return DecodeResult
        public bool TryDecode<T>(string token, PayloadParser<T> payloadParser, out T payloadResult)
        {
            // HttpContext ctx = null;
            // ctx.Request.
            // ctx.he


            var (header, payload, signature) = Split(token);

            // TryFromBase64Chars
            Span<byte> bytes = stackalloc byte[header.Count];
            Convert.TryFromBase64Chars(header.AsSpan(), bytes, out var bytesWritten);

            var headerString = Encoding.UTF8.GetString(bytes.Slice(0, bytesWritten));

            var reader = new Utf8JsonReader(bytes.Slice(0, bytesWritten), true, default(JsonReaderState));

            reader.Read();
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                // invalid
            }

            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.EndObject:
                        break;
                    case JsonTokenType.PropertyName:
                        if (reader.TextEquals("alg"))
                        {
                            // try to read algorithm span.
                            if (reader.Read())
                            {
                                var algorithm = reader.ValueSpan;
                                // select algorithm
                            }
                        }
                        else
                        {
                            reader.Read(); // maybe "typ:JWT" but not check.
                        }
                        break;
                    default:
                        throw new Exception();
                }
            }

            // new Utf8JsonWriter(

            // TODO:get expiry or etc.
            payloadResult = payloadParser(payload.AsSpan());


            // verify!
            return true;
        }


    }

    public interface IJwtAlgorithmResolver
    {
        IJwtAlgorithm Resolve(ReadOnlySpan<byte> name);
    }

    public class UnsafeNoneAlgorithm
    {
        byte[] name = Encoding.UTF8.GetBytes("Name");
        public ReadOnlySpan<byte> Name => name;


    }



    public readonly struct StringSegment
    {
        public readonly string Text;
        public readonly int Offset;
        public readonly int Count;

        public StringSegment(string text, int offset, int count)
        {
            Text = text;
            Offset = offset;
            Count = count;
        }

        public ReadOnlySpan<char> AsSpan()
        {
            return Text.AsSpan(Offset, Count);
        }

        public override string ToString()
        {
            return Text.Substring(Offset, Count);
        }
    }


    public interface IJwtEncoder
    {

    }


    public interface IJwtDecoder
    {

    }

    public interface IJwtAlgorithm
    {
        ReadOnlySpan<byte> Header { get; }
        ReadOnlySpan<byte> HeaderBase64WithDot { get; }
    }




    public sealed class HMACSHA256Algorithm : IJwtAlgorithm
    {
        static readonly byte[] header = Encoding.UTF8.GetBytes(@"{""alg"":""HS256"",""typ"":""JWT""}");
        static readonly byte[] headerBase64WithDot = Encoding.UTF8.GetBytes(Convert.ToBase64String(header) + ".");

        ReadOnlySpan<byte> Header => header;

        ReadOnlySpan<byte> IJwtAlgorithm.Header => throw new NotImplementedException();

        ReadOnlySpan<byte> HeaderBase64WithDot => headerBase64WithDot;

        ReadOnlySpan<byte> IJwtAlgorithm.HeaderBase64WithDot => throw new NotImplementedException();

        public byte[] Sign(byte[] key, ReadOnlySpan<byte> source, IBufferWriter<byte> writer)
        {
            using (var sha = new HMACSHA256(key))
            {
                Span<byte> dest = stackalloc byte[32];

                if (sha.TryComputeHash(source, dest, out var bytesWritten) && bytesWritten == 32)
                {
                    // writer.Write(
                }
                else
                {
                    throw new InvalidOperationException("Can not compute hash.");
                }
            }

            throw new NotImplementedException();
        }
    }

    public struct JwtHeader
    {

    }

    public struct JwtPayload
    {

    }


    internal class ReservedConstants
    {
        public const string Issuer = "iss";
        public const string Subject = "sub";
        public const string Audience = "aud";
        public const string Expiration = "exp";
        public const string NotBefore = "nbf";
        public const string IssuedAt = "iat";
        public const string JwtIdentifier = "jti";
    }
}
