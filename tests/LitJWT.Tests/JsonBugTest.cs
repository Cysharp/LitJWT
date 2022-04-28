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
    }

    public class User
    {
        public string Name { get; set; }
    }
}
