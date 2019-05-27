using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ConsoleApp
{
    class Program
    {
        static void Main(string[] args)
        {
            {
                var encoder = new JWT.JwtEncoder(new JWT.Algorithms.HMACSHA256Algorithm(), new JWT.Serializers.JsonNetSerializer(), new JWT.JwtBase64UrlEncoder());

                var encoded = encoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, Encoding.UTF8.GetBytes("hogehogehogehoge"));
                Console.WriteLine(encoded);

                var decoder = new LitJWT.JwtDecoder(new LitJWT.JwtAlgorithmResolver(new LitJWT.Algorithms.HS256Algorithm(Encoding.UTF8.GetBytes("hogehogehogehoge"))));

                decoder.TryDecode<object>(encoded, x => null, out var r);
            }

            {
                var encoder = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(Encoding.UTF8.GetBytes("hogehogehogehoge")));
                var result = encoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
                Console.WriteLine(result);
            }

            {
                //Microsoft.IdentityModel.JsonWebTokens.JwtTokenUtilities.GenerateKeyBytes(

                var handler = new JwtSecurityTokenHandler()
                {
                    SetDefaultTimesOnTokenCreation = false
                };
                var keyString = "hogehogehogehoge";
                var key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));


                var claimIdentity = new ClaimsIdentity(new[] { new Claim("hoge", "hugahuga"), new Claim("hage", "nanonano") });
                var token = handler.CreateJwtSecurityToken(subject: claimIdentity, signingCredentials: new SigningCredentials(key, "HS256"));
                Console.WriteLine(token);
                Console.WriteLine(handler.WriteToken(token));
                //Console.WriteLine(token);


                // handler.CreateToken(


                //.ValidateToken("foo", new Microsoft.IdentityModel.Tokens.TokenValidationParameters()

            }
        }
    }
}
