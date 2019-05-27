using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Csv;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using JWT;
using LitJWT;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Benchmark
{
    class Program
    {
        static void Main(string[] args)
        {
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
        }
    }

    public class BenchmarkConfig : ManualConfig
    {
        public BenchmarkConfig()
        {
            // run quickly:)
            var baseConfig = Job.ShortRun.WithIterationCount(1).WithWarmupCount(1);

            // Add(baseConfig.With(Runtime.Clr).With(Jit.RyuJit).With(Platform.X64));
            Add(baseConfig.With(Runtime.Core).With(Jit.RyuJit).With(Platform.X64));

            Add(MarkdownExporter.GitHub);
            Add(CsvExporter.Default);
            Add(MemoryDiagnoser.Default);
        }
    }

    [Config(typeof(BenchmarkConfig))]
    public class JwtEncode
    {
        JWT.JwtEncoder jwtEncoder;
        LitJWT.JwtEncoder litJwtEncoder;
        JwtSecurityTokenHandler jwtHandler;
        byte[] key;
        SymmetricSecurityKey handlerKey;

        public JwtEncode()
        {
            key = Encoding.UTF8.GetBytes("hogehogehogehoge");
            litJwtEncoder = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(key));
            jwtEncoder = new JWT.JwtEncoder(new JWT.Algorithms.HMACSHA256Algorithm(), new JWT.Serializers.JsonNetSerializer(), new JWT.JwtBase64UrlEncoder());

            jwtHandler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };
            handlerKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);
        }

        [Benchmark(Baseline = true)]
        public string LitJwt()
        {
            return litJwtEncoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string JwtDotNet()
        {
            return jwtEncoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, key);
        }

        [Benchmark]
        public string MicrosoftIdentityModelJwt()
        {
            var claimIdentity = new ClaimsIdentity(new[] { new Claim("hoge", "hugahuga"), new Claim("hage", "nanonano") });
            var token = jwtHandler.CreateJwtSecurityToken(subject: claimIdentity, signingCredentials: new SigningCredentials(handlerKey, "HS256"));
            return jwtHandler.WriteToken(token);

        }
    }

    public class Payload
    {
        public string hoge { get; set; }
        public string hage { get; set; }
    }

    [Config(typeof(BenchmarkConfig))]
    public class JwtDecode
    {
        JWT.JwtDecoder jwtDecoder;
        LitJWT.JwtDecoder litJwtDecoder;
        JwtSecurityTokenHandler jwtHandler;
        byte[] key;
        SymmetricSecurityKey handlerKey;

        string tokenA;
        string tokenB;
        string tokenC;

        public JwtDecode()
        {
            key = Encoding.UTF8.GetBytes("hogehogehogehoge");
            litJwtDecoder = new LitJWT.JwtDecoder(new LitJWT.JwtAlgorithmResolver(new LitJWT.Algorithms.HS256Algorithm(key)));
            jwtDecoder = new JWT.JwtDecoder(new JWT.Serializers.JsonNetSerializer(), new JWT.JwtValidator(new JWT.Serializers.JsonNetSerializer(), new UtcDateTimeProvider()), new JWT.JwtBase64UrlEncoder());

            jwtHandler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };
            handlerKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);

            tokenA = new JwtEncode().LitJwt();
            tokenB = new JwtEncode().JwtDotNet();
            tokenC = new JwtEncode().MicrosoftIdentityModelJwt();
        }

        [Benchmark(Baseline = true)]
        public Payload LitJwt()
        {
            litJwtDecoder.TryDecode(tokenA, x => Utf8Json.JsonSerializer.Deserialize<Payload>(x.ToArray()), out var result);
            return result;
        }

        [Benchmark]
        public Payload JwtDotNet()
        {
            return jwtDecoder.DecodeToObject<Payload>(tokenB, key, true);
        }

        [Benchmark]
        public JwtPayload MicrosoftIdentityModelJwt()
        {
            var claimIdentity = new ClaimsIdentity(new[] { new Claim("hoge", "hugahuga"), new Claim("hage", "nanonano") });
            var token = jwtHandler.CreateJwtSecurityToken(subject: claimIdentity, signingCredentials: new SigningCredentials(handlerKey, "HS256"));

            var huga = jwtHandler.ReadJwtToken(tokenC);
            return huga.Payload;

            //var claimPrincipal = jwtHandler.ValidateToken(tokenC, new TokenValidationParameters
            //{
            //    vali
            //    IssuerSigningKey = handlerKey
            //}, out var securityToken);
            //return jwtHandler.WriteToken(token);

        }
    }


    [Config(typeof(BenchmarkConfig))]
    public class EncryptionTypeEncode
    {
        LitJWT.JwtEncoder hs256;
        LitJWT.JwtEncoder hs384;
        LitJWT.JwtEncoder hs512;
        LitJWT.JwtEncoder rs256;
        LitJWT.JwtEncoder rs384;
        LitJWT.JwtEncoder rs512;
        Payload payload;
        public EncryptionTypeEncode()
        {
            payload = new Payload { hoge = "hugahuga", hage = "nanonano" };
            var rsaParams = RSA.Create().ExportParameters(true);
            hs256 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey()));
            hs384 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS384Algorithm(LitJWT.Algorithms.HS384Algorithm.GenerateRandomRecommendedKey()));
            hs512 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS512Algorithm(LitJWT.Algorithms.HS512Algorithm.GenerateRandomRecommendedKey()));
            rs256 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS256Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
            rs384 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS384Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
            rs512 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS512Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
        }

        [Benchmark]
        public string HS256()
        {
            return hs256.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string HS384()
        {
            return hs384.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string HS512()
        {
            return hs512.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string RS256()
        {
            return rs256.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string RS384()
        {
            return rs384.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public string RS512()
        {
            return rs512.Encode(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }
    }




    [Config(typeof(BenchmarkConfig))]
    public class DecryptionTypeEncode
    {
        LitJWT.JwtDecoder hs256;
        LitJWT.JwtDecoder hs384;
        LitJWT.JwtDecoder hs512;
        LitJWT.JwtDecoder rs256;
        LitJWT.JwtDecoder rs384;
        LitJWT.JwtDecoder rs512;
        Payload payload;

        byte[] b1;
        byte[] b2;
        byte[] b3;
        byte[] b4;
        byte[] b5;
        byte[] b6;

        public DecryptionTypeEncode()
        {
            var rsaParams = RSA.Create().ExportParameters(true);
            payload = new Payload { hoge = "hugahuga", hage = "nanonano" };

            var ehs256 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS256Algorithm(LitJWT.Algorithms.HS256Algorithm.GenerateRandomRecommendedKey()));
            var ehs384 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS384Algorithm(LitJWT.Algorithms.HS384Algorithm.GenerateRandomRecommendedKey()));
            var ehs512 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HS512Algorithm(LitJWT.Algorithms.HS512Algorithm.GenerateRandomRecommendedKey()));
            var ers256 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS256Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
            var ers384 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS384Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));
            var ers512 = new LitJWT.JwtEncoder(new LitJWT.Algorithms.RS512Algorithm(() => RSA.Create(rsaParams), () => RSA.Create(rsaParams)));

            hs256 = new LitJWT.JwtDecoder(ehs256.SignAlgorithm);
            hs384 = new LitJWT.JwtDecoder(ehs384.SignAlgorithm);
            hs512 = new LitJWT.JwtDecoder(ehs512.SignAlgorithm);
            rs256 = new LitJWT.JwtDecoder(ers256.SignAlgorithm);
            rs384 = new LitJWT.JwtDecoder(ers384.SignAlgorithm);
            rs512 = new LitJWT.JwtDecoder(ers512.SignAlgorithm);

            b1 = ehs256.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
            b2 = ehs384.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
            b3 = ehs512.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
            b4 = ers256.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
            b5 = ers384.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
            b6 = ers512.EncodeAsUtf8Bytes(payload, null, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
        }

        [Benchmark]
        public DecodeResult HS256()
        {
            return hs256.TryDecode(b1, x => (object)null, out _);
        }

        [Benchmark]
        public DecodeResult HS384()
        {
            return hs384.TryDecode(b2, x => (object)null, out _);
        }

        [Benchmark]
        public DecodeResult HS512()
        {
            return hs512.TryDecode(b3, x => (object)null, out _);
        }

        [Benchmark]
        public DecodeResult RS256()
        {
            return rs256.TryDecode(b4, x => (object)null, out _);
        }

        [Benchmark]
        public DecodeResult RS384()
        {
            return rs384.TryDecode(b5, x => (object)null, out _);
        }

        [Benchmark]
        public DecodeResult RS512()
        {
            return rs512.TryDecode(b6, x => (object)null, out _);
        }
    }
}