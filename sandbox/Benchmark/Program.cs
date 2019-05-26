using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Diagnosers;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Exporters.Csv;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;
using JWT;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
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
            litJwtEncoder = new LitJWT.JwtEncoder(new LitJWT.Algorithms.HMACSHA256Algorithm(key));
            jwtEncoder = new JWT.JwtEncoder(new JWT.Algorithms.HMACSHA256Algorithm(), new JWT.Serializers.JsonNetSerializer(), new JWT.JwtBase64UrlEncoder());

            jwtHandler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };
            handlerKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);
        }

        [Benchmark(Baseline = true)]
        public string CysharpJWT()
        {
            return litJwtEncoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, (x, writer) => writer.Write(Utf8Json.JsonSerializer.SerializeUnsafe(x)));
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
            litJwtDecoder = new LitJWT.JwtDecoder(new LitJWT.JwtAlgorithmResolver(new LitJWT.Algorithms.HMACSHA256Algorithm(key)));
            jwtDecoder = new JWT.JwtDecoder(new JWT.Serializers.JsonNetSerializer(),new JWT.JwtValidator(new JWT.Serializers.JsonNetSerializer(), new UtcDateTimeProvider()),  new JWT.JwtBase64UrlEncoder());

            jwtHandler = new JwtSecurityTokenHandler()
            {
                SetDefaultTimesOnTokenCreation = false
            };
            handlerKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);

            tokenA = new JwtEncode().CysharpJWT();
            tokenB = new JwtEncode().JwtDotNet();
            tokenC = new JwtEncode().MicrosoftIdentityModelJwt();
        }

        [Benchmark(Baseline = true)]
        public Payload CysharpJWT()
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
}
