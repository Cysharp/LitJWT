using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LitJWT
{
    public class JwtAlgorithmResolver
    {
        ReadOnlyUtf8StringDictionary<IJwtAlgorithm> algorithms;
        ReadOnlyUtf8StringDictionary<IJwtAlgorithm> algorithmsBase64UrlMatch;

        public JwtAlgorithmResolver(params IJwtAlgorithm[] algorithms)
        {
            {
                var pairs = algorithms.Select(x => new KeyValuePair<byte[], IJwtAlgorithm>(Encoding.UTF8.GetBytes(x.AlgName), x));
                this.algorithms = new ReadOnlyUtf8StringDictionary<IJwtAlgorithm>(pairs);
            }
            {
                var pairs = algorithms.Select(x => new KeyValuePair<byte[], IJwtAlgorithm>(x.HeaderBase64Url.ToArray(), x));
                this.algorithmsBase64UrlMatch = new ReadOnlyUtf8StringDictionary<IJwtAlgorithm>(pairs);
            }
        }

        internal IJwtAlgorithm ResolveFromBase64Header(ReadOnlySpan<byte> header)
        {
            return algorithmsBase64UrlMatch.TryGetValue(header, out var result) ? result : null;
        }

        public IJwtAlgorithm Resolve(ReadOnlySpan<byte> name)
        {
            return algorithms.TryGetValue(name, out var result) ? result : null;
        }
    }

    public interface IJwtAlgorithm
    {
        string AlgName { get; }
        ReadOnlySpan<byte> HeaderBase64Url { get; }
        int HashSize { get; }
        void Sign(ReadOnlySpan<byte> source, Span<byte> dest);
        bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature);
    }
}

namespace LitJWT.Algorithms
{
    public abstract class SymmetricJwtAlgorithmBase : IJwtAlgorithm, IDisposable
    {
        readonly byte[] key;

        [ThreadStatic] HashAlgorithm hash;
        ConcurrentBag<HashAlgorithm> generateAlgorithms = new ConcurrentBag<HashAlgorithm>();
        byte[] header;

        public ReadOnlySpan<byte> HeaderBase64Url => header;

        protected SymmetricJwtAlgorithmBase(byte[] key)
        {
            this.key = key;

            var alg = Encoding.UTF8.GetBytes($@"{{""alg"":""{AlgName}"",""typ"":""JWT""}}");
            var len = Base64.GetBase64UrlEncodeLength(alg.Length);
            Span<byte> buffer = stackalloc byte[len];
            Base64.TryToBase64UrlUtf8(alg, buffer, out _);
            header = buffer.ToArray();
        }

        protected abstract HashAlgorithm CreateHashAlgorithm(byte[] key);
        public abstract string AlgName { get; }

        public abstract int HashSize { get; }

        public void Sign(ReadOnlySpan<byte> source, Span<byte> dest)
        {
            GetHash().TryComputeHash(source, dest, out _);
        }

        public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            Span<byte> buffer = stackalloc byte[HashSize];
            GetHash().TryComputeHash(data, buffer, out _);
            return buffer.SequenceEqual(signature);
        }

        HashAlgorithm GetHash()
        {
            if (hash == null)
            {
                hash = CreateHashAlgorithm(key);
                generateAlgorithms.Add(hash);
            }
            return hash;
        }
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            foreach (var item in generateAlgorithms)
            {
                item.Dispose();
            }
        }

        ~SymmetricJwtAlgorithmBase()
        {
            Dispose(false);
        }
    }

    public sealed class HS256Algorithm : SymmetricJwtAlgorithmBase
    {
        public override string AlgName => "HS256";

        public override int HashSize => 32;

        public HS256Algorithm(byte[] key)
            : base(key)
        {
        }

        protected override HashAlgorithm CreateHashAlgorithm(byte[] key)
        {
            return new HMACSHA256(key);
        }

        public static byte[] GenerateRandomRecommendedKey()
        {
            var key = new byte[64];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }

    public sealed class HS384Algorithm : SymmetricJwtAlgorithmBase
    {
        public override string AlgName => "HS384";

        public override int HashSize => 48;

        public HS384Algorithm(byte[] key)
            : base(key)
        {
        }

        protected override HashAlgorithm CreateHashAlgorithm(byte[] key)
        {
            return new HMACSHA384(key);
        }

        public static byte[] GenerateRandomRecommendedKey()
        {
            var key = new byte[128];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }

    public sealed class HS512Algorithm : SymmetricJwtAlgorithmBase
    {
        public override string AlgName => "HS512";

        public override int HashSize => 56;


        public HS512Algorithm(byte[] key)
            : base(key)
        {
        }

        protected override HashAlgorithm CreateHashAlgorithm(byte[] key)
        {
            return new HMACSHA512(key);
        }

        public static byte[] GenerateRandomRecommendedKey()
        {
            var key = new byte[128];
            RandomNumberGenerator.Fill(key);
            return key;
        }
    }

    public abstract class RSAJwtAlgorithmBase : IJwtAlgorithm, IDisposable
    {
        readonly X509Certificate2 cert;

        [ThreadStatic] RSA publicKey;
        [ThreadStatic] RSA privateKey;
        ConcurrentBag<AsymmetricAlgorithm> generateAlgorithms = new ConcurrentBag<AsymmetricAlgorithm>();

        byte[] header;
        public ReadOnlySpan<byte> HeaderBase64Url => header;

        public RSAJwtAlgorithmBase(X509Certificate2 cert)
        {
            this.cert = cert;

            var alg = Encoding.UTF8.GetBytes($@"{{""alg"":""{AlgName}"",""typ"":""JWT""}}");
            var len = Base64.GetBase64UrlEncodeLength(alg.Length);
            Span<byte> buffer = stackalloc byte[len];
            Base64.TryToBase64UrlUtf8(alg, buffer, out _);
            header = buffer.ToArray();
        }

        public abstract string AlgName { get; }

        public abstract int HashSize { get; }

        public abstract HashAlgorithmName HashAlgorithmName { get; }
        public abstract RSASignaturePadding RSASignaturePadding { get; }

        public void Sign(ReadOnlySpan<byte> source, Span<byte> dest)
        {
            privateKey.TrySignData(source, dest, HashAlgorithmName, RSASignaturePadding, out _);
        }

        public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            return publicKey.VerifyData(data, signature, HashAlgorithmName, RSASignaturePadding);
        }

        RSA GetPublicKey()
        {
            if (publicKey == null)
            {
                publicKey = cert.GetRSAPublicKey();
                generateAlgorithms.Add(publicKey);
            }
            return publicKey;
        }

        RSA GetPrivateKey()
        {
            if (privateKey == null)
            {
                privateKey = cert.GetRSAPrivateKey();
                generateAlgorithms.Add(privateKey);
            }
            return privateKey;
        }


        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            foreach (var item in generateAlgorithms)
            {
                item.Dispose();
            }
        }

        ~RSAJwtAlgorithmBase()
        {
            Dispose(false);
        }
    }

    public sealed class RS256Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "RS256";

        public override int HashSize => 32;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pkcs1;

        public RS256Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class RS384Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "RS384";

        public override int HashSize => 48;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA384;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pkcs1;

        public RS384Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class RS512Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "RS512";

        public override int HashSize => 64;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pkcs1;

        public RS512Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class PS256Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "PS256";

        public override int HashSize => 32;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pss;

        public PS256Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class PS384Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "PS384";

        public override int HashSize => 48;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA384;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pss;

        public PS384Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class PS512Algorithm : RSAJwtAlgorithmBase
    {
        public override string AlgName => "PS512";

        public override int HashSize => 64;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        public override RSASignaturePadding RSASignaturePadding => RSASignaturePadding.Pss;

        public PS512Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public abstract class ESJwtAlgorithmBase : IJwtAlgorithm, IDisposable
    {
        readonly X509Certificate2 cert;

        [ThreadStatic] ECDsa publicKey;
        [ThreadStatic] ECDsa privateKey;
        ConcurrentBag<AsymmetricAlgorithm> generateAlgorithms = new ConcurrentBag<AsymmetricAlgorithm>();

        byte[] header;
        public ReadOnlySpan<byte> HeaderBase64Url => header;

        public ESJwtAlgorithmBase(X509Certificate2 cert)
        {
            this.cert = cert;

            var alg = Encoding.UTF8.GetBytes($@"{{""alg"":""{AlgName}"",""typ"":""JWT""}}");
            var len = Base64.GetBase64UrlEncodeLength(alg.Length);
            Span<byte> buffer = stackalloc byte[len];
            Base64.TryToBase64UrlUtf8(alg, buffer, out _);
            header = buffer.ToArray();
        }

        public abstract string AlgName { get; }

        public abstract int HashSize { get; }

        public abstract HashAlgorithmName HashAlgorithmName { get; }

        public void Sign(ReadOnlySpan<byte> source, Span<byte> dest)
        {
            privateKey.TrySignData(source, dest, HashAlgorithmName, out _);
        }

        public bool Verify(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
        {
            return publicKey.VerifyData(data, signature, HashAlgorithmName);
        }

        ECDsa GetPublicKey()
        {
            if (publicKey == null)
            {
                publicKey = cert.GetECDsaPublicKey();
                generateAlgorithms.Add(publicKey);
            }
            return publicKey;
        }

        ECDsa GetPrivateKey()
        {
            if (privateKey == null)
            {
                privateKey = cert.GetECDsaPrivateKey();
                generateAlgorithms.Add(privateKey);
            }
            return privateKey;
        }


        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            foreach (var item in generateAlgorithms)
            {
                item.Dispose();
            }
        }

        ~ESJwtAlgorithmBase()
        {
            Dispose(false);
        }
    }

    public sealed class ES256Algorithm : ESJwtAlgorithmBase
    {
        public override string AlgName => "ES256";

        public override int HashSize => 32;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA256;

        public ES256Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class ES384Algorithm : ESJwtAlgorithmBase
    {
        public override string AlgName => "ES384";

        public override int HashSize => 48;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA384;

        public ES384Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }

    public sealed class ES512Algorithm : ESJwtAlgorithmBase
    {
        public override string AlgName => "ES512";

        public override int HashSize => 64;

        public override HashAlgorithmName HashAlgorithmName => HashAlgorithmName.SHA512;

        public ES512Algorithm(X509Certificate2 cert) : base(cert)
        {
        }
    }
}