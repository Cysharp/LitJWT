using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace LitJWT.Tests
{
    public class JsonBugTest
    {
        [Fact]
        public void Test()
        {
            var key = new byte[] { 1, 2, 3 };
            var encoder = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var decoder = new LitJWT.JwtDecoder(encoder.SignAlgorithm);
            var bytes = encoder.EncodeAsUtf8Bytes(new User { Name = "foo\\" }, System.TimeSpan.FromMinutes(5), (x, writer) => writer.Write(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(x)));
            var result = decoder.TryDecode(bytes, x => System.Text.Json.JsonSerializer.Deserialize<User>(x), out var session);
            session.Name.Should().Be("foo\\");
        }

        // https://github.com/Cysharp/LitJWT/issues/15
        [Fact]
        public void TryDecodeShouldNotThrowException()
        {
            var jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mvdjdBZKOtWyQl54xAd8C9kY0RUyq-z26qNTjFR1DKA";

            var key = Encoding.UTF8.GetBytes("a");
            var decoder = new LitJWT.JwtDecoder(new LitJWT.Algorithms.HS256Algorithm(key));
            var result = decoder.TryDecode<TestPayload>(jwt, out var p);
            result.Should().Be(DecodeResult.Success);

            p.sub.Should().Be("1234567890");
            p.name.Should().Be("John Doe");
            p.iat.Should().Be(1516239022);

            var invalidjwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaGggRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.mvdjdBZKOtWyQl54xAd8C9kY0RUyq-z26qNTjFR1DKA";
            var result2 = decoder.TryDecode<TestPayload>(invalidjwt, out var p2);
            result2.Should().Be(DecodeResult.InvalidPayloadFormat);
        }
    }

    public class TestPayload
    {
        public string sub { get; set; }
        public string name { get; set; }
        public int iat { get; set; }
    }

    public class User
    {
        public string Name { get; set; }
    }
}
