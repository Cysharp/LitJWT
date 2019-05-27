using System;
using System.Linq;
using FluentAssertions;
using Xunit;
using System.Collections.Generic;
using System.Text;
using Newtonsoft.Json;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using RandomFixtureKit;
using System.Buffers;

namespace LitJWT.Tests
{
    public class EncodeTest
    {
        public class Payload
        {
            public string Foo { get; set; }
            public int Bar { get; set; }
        }

        string GetReferenceToken(byte[] key, Payload payload, int? withExpiry)
        {
            var jwtHandler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };
            var handlerKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);
            var credentials = new SigningCredentials(handlerKey, "HS256");
            var claimIdentity = new ClaimsIdentity(new[] { new Claim("Foo", payload.Foo), new Claim("Bar", payload.Bar.ToString(), ClaimValueTypes.Integer32) });
            if (withExpiry != null)
            {
                claimIdentity.AddClaim(new Claim("exp", withExpiry.Value.ToString(), ClaimValueTypes.Integer32));
            }
            var token = jwtHandler.CreateJwtSecurityToken(subject: claimIdentity, signingCredentials: new SigningCredentials(handlerKey, "HS256"));
            return jwtHandler.WriteToken(token);
        }

        [Fact]
        public void JwtEncode()
        {
            foreach (var payload in FixtureFactory.CreateMany<Payload>(99))
            {
                var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
                var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var result = encoder.Encode(payload, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                result.Should().Be(GetReferenceToken(key, payload, null));
            }
        }

        [Fact]
        public void JwtEncodeWithExpire()
        {
            foreach (var payload in FixtureFactory.CreateMany<Payload>(99))
            {
                var key = LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey();
                var encoder = new JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));

                var expireDate = DateTimeOffset.UtcNow.AddSeconds(99);

                var result = encoder.Encode(payload, expireDate, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));

                result.Should().Be(GetReferenceToken(key, payload, (int)expireDate.ToUnixTimeSeconds()));
            }
        }
    }

}
