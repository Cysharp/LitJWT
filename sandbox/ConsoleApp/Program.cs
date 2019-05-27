using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

using LitJWT;
using LitJWT.Algorithms;
using Newtonsoft.Json;
using System.Security.Cryptography;

namespace ConsoleApp
{
    class Program
    {
        public class PayloadSample
        {
            public string foo { get; set; }
            public string bar { get; set; }
        }

        static void Main(string[] args)
        {
            //// Get recommended-size random key.
            //var key = HS256Algorithm.GenerateRandomRecommendedKey();

            //// Create encoder, JwtEncoder is thread-safe and recommend to store static/singleton.
            //var encoder = new JwtEncoder(new HS256Algorithm(key));

            //// Encode with payload, expire, and use specify payload serializer.
            //var token = encoder.Encode(new PayloadSample { foo = "pay", bar = "load" }, TimeSpan.FromMinutes(30),
            //    (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));

            //var token2 = encoder.Encode(new PayloadSample { foo = "pay", bar = "load" }, TimeSpan.FromMinutes(30),
            //    (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(x))));


            ////byte[] input;
            ////Convert.ToBase64String(input).TrimEnd('=').Replace('+', '-').Replace('/', '_');



            //// Create decoder, JwtDecoder is also thread-safe so recommend to store static/singleton.
            //var decoder = new JwtDecoder(encoder.SignAlgorithm);
            ////var result = decoder.TryDecode(token, x => Utf8Json.JsonSerializer.Deserialize<PayloadSample>(x.ToArray()), out var payload);

            //var result = decoder.TryDecode(token, x => JsonConvert.DeserializeObject<PayloadSample>(Encoding.UTF8.GetString(x)), out var payload);

            //if (result == DecodeResult.Success)
            //{
            //    Console.WriteLine((payload.foo, payload.bar));
            //}

            //Console.WriteLine(token);

            var payload = new  { hoge = "hugahuga", hage = "nanonano" };
            var rsaParams = RSA.Create().ExportParameters(true);
            var rs256 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS256Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
            var foo = rs256.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));



        }
    }
}
