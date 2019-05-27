using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace LitJWT
{
    class Program
    {
        static void Main(string[] args)
        {
            var parameters = RSA.Create().ExportParameters(true);

            var data = new byte[] { 10, 20, 30, 40, 50 };
            var signature = new byte[128];
            var okok = RSA.Create(parameters).TrySignData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, out var written);


            var ok = RSA.Create(parameters).VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            System.Console.WriteLine(ok);



            var algorithm = new LitJWT.Algorithms.RS256Algorithm(() => RSA.Create(parameters), () => RSA.Create(parameters));

            Span<byte> signature2 = new byte[256];
            algorithm.Sign(data, signature2);

            var ok2 = algorithm.Verify(data, signature2);
            Console.WriteLine(ok2);

            //var encoder = new LitJWT.JwtEncoder(algorithm);


            //var result = encoder.Encode(new { hoge = "hugahuga", hage = "nanonano" }, null, (x, writer) => writer.Write(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject((x)))));

            //var decoder = new LitJWT.JwtDecoder(algorithm);
            //var decodeResult = decoder.TryDecode(result, x => (object)null, out _);


        }
    }




}
