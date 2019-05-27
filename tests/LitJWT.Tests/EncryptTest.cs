using Newtonsoft.Json;
using FluentAssertions;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit;

namespace LitJWT.Tests
{
    public class RSATest
    {
        [Fact]
        public void Rsa()
        {
            var parameters = RSA.Create().ExportParameters(true);

            var sameRsa = RSA.Create(parameters);

            var algorithm = new LitJWT.Algorithms.RS256Algorithm(() => sameRsa, () => sameRsa);

            var encoder = new LitJWT.JwtEncoder(algorithm);

            var result = encoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject((x)))));

            var decoder = new LitJWT.JwtDecoder(algorithm);
            var decodeResult = decoder.TryDecode(result, x => (object)null, out _);
            decodeResult.Should().Be(DecodeResult.Success);

        }
    }
}
