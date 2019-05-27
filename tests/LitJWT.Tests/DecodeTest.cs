using Newtonsoft.Json;
using System.Linq;
using FluentAssertions;
using RandomFixtureKit;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace LitJWT.Tests
{
    public class DecodeTest
    {
        public class Payload
        {
            public string Foo { get; set; }
            public int Bar { get; set; }
        }
        public class PayloadNbf
        {
            public string Foo { get; set; }
            public int Bar { get; set; }
            public long nbf { get; set; }
        }
        public class PayloadExp
        {
            public string Foo { get; set; }
            public int Bar { get; set; }
            public long exp { get; set; }
        }
        [Fact]
        public void StandardDecode()
        {
            foreach (var payload in FixtureFactory.CreateMany<Payload>(99))
            {
                var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
                var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.Success);
                decodedPayload.Foo.Should().Be(payload.Foo);
                decodedPayload.Bar.Should().Be(payload.Bar);
            }
        }

        [Fact]
        public void Fail()
        {
            var payload = FixtureFactory.Create<Payload>();
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

            var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var span = result.ToCharArray().AsSpan();
                span[4] = '?';

                var decodeResult = decoder.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.InvalidBase64UrlHeader);
            }
            {
                var span = result.ToCharArray().AsSpan();

                var decoder2 = new JwtDecoder(new LitJWT.Algorithms.HS384Algorithm(key));
                var decodeResult = decoder2.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.AlgorithmNotExists);
            }
            {
                var span = result.ToCharArray().AsSpan();
                span[span.Length - 10] = 'A';
                span[span.Length - 11] = 'B';
                span[span.Length - 12] = 'C'; // maybe break signature

                var decodeResult = decoder.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.FailedVerifySignature);
            }
        }

        [Fact]
        public void VerifyExp()
        {
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var payload = new PayloadExp { Bar = 1, Foo = "foo", exp = (DateTimeOffset.UtcNow - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);
                decodeResult.Should().Be(DecodeResult.FailedVerifyExpire);
            }

            {
                var payload = new PayloadExp { Bar = 1, Foo = "foo", exp = (DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);
                decodeResult.Should().Be(DecodeResult.Success);
            }
        }

        [Fact]
        public void VerifyNbf()
        {
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var payload = new PayloadNbf { Bar = 1, Foo = "foo", nbf = (DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));


                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.FailedVerifyNotBefore);
            }
            {
                var payload = new PayloadNbf { Bar = 1, Foo = "foo", nbf = (DateTimeOffset.UtcNow - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));


                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.Success);
            }
        }




        [Fact]
        public void StandardDecodeUtf8()
        {
            foreach (var payload in FixtureFactory.CreateMany<Payload>(99))
            {
                var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
                var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.Success);
                decodedPayload.Foo.Should().Be(payload.Foo);
                decodedPayload.Bar.Should().Be(payload.Bar);
            }
        }

        [Fact]
        public void FailUtf8()
        {
            var payload = FixtureFactory.Create<Payload>();
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

            var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var span = result.ToArray().AsSpan();
                span[4] = (byte)'?';

                var decodeResult = decoder.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.InvalidBase64UrlHeader);
            }
            {
                var span = result.ToArray().AsSpan();

                var decoder2 = new JwtDecoder(new LitJWT.Algorithms.HS384Algorithm(key));
                var decodeResult = decoder2.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.AlgorithmNotExists);
            }
            {
                var span = result.ToArray().AsSpan();
                span[span.Length - 10] = (byte)'A';
                span[span.Length - 11] = (byte)'B';
                span[span.Length - 12] = (byte)'C'; // maybe break signature

                var decodeResult = decoder.TryDecode(span, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.FailedVerifySignature);
            }
        }

        [Fact]
        public void VerifyExpUtf8()
        {
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var payload = new PayloadExp { Bar = 1, Foo = "foo", exp = (DateTimeOffset.UtcNow - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);
                decodeResult.Should().Be(DecodeResult.FailedVerifyExpire);
            }

            {
                var payload = new PayloadExp { Bar = 1, Foo = "foo", exp = (DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);
                decodeResult.Should().Be(DecodeResult.Success);
            }
        }

        [Fact]
        public void VerifyNbfUtf8()
        {
            var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
            var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var decoder = new JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));

            {
                var payload = new PayloadNbf { Bar = 1, Foo = "foo", nbf = (DateTimeOffset.UtcNow + TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));


                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.FailedVerifyNotBefore);
            }
            {
                var payload = new PayloadNbf { Bar = 1, Foo = "foo", nbf = (DateTimeOffset.UtcNow - TimeSpan.FromSeconds(10)).ToUnixTimeSeconds() };
                var result = encoder.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));


                var decodeResult = decoder.TryDecode(result, x => JsonConvert.DeserializeObject<Payload>(Encoding.UTF8.GetString(x)), out var decodedPayload);

                decodeResult.Should().Be(DecodeResult.Success);
            }
        }
    }
}
