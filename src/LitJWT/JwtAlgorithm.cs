using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Collections.Concurrent;

namespace LitJWT
{
    public interface IJwtAlgorithmResolver
    {
        IJwtAlgorithm Resolve(ReadOnlySpan<byte> name);
    }

    public class JwtAlgorithmResolver : IJwtAlgorithmResolver
    {
        ReadOnlyUtf8StringDictionary<IJwtAlgorithm> algorithms;

        public JwtAlgorithmResolver(params IJwtAlgorithm[] algorithms)
        {
            var pairs = algorithms.Select(x => new KeyValuePair<byte[], IJwtAlgorithm>(Encoding.UTF8.GetBytes(x.AlgName), x));
            this.algorithms = new ReadOnlyUtf8StringDictionary<IJwtAlgorithm>(pairs);
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
    }
}

namespace LitJWT.Algorithms
{
    public abstract class JwtAlgorithmBase : IJwtAlgorithm, IDisposable
    {
        readonly byte[] key;

        [ThreadStatic] HashAlgorithm hash;
        ConcurrentBag<HashAlgorithm> generateAlgorithms = new ConcurrentBag<HashAlgorithm>();
        byte[] header;

        public ReadOnlySpan<byte> HeaderBase64Url => header;

        protected JwtAlgorithmBase(byte[] key)
        {
            this.key = key;

            var alg = Encoding.UTF8.GetBytes($@"{{""alg"":""{AlgName}"",""typ"":""JWT""}}");
            var len = Base64.GetBase64UrlEncodeLength(alg.Length);
            Span<byte> buffer = stackalloc byte[len];
            Base64.TryEncodeBase64Url(alg, buffer, out _);
            header = buffer.ToArray();
        }

        protected abstract HashAlgorithm CreateHashAlgorithm(byte[] key);
        public abstract string AlgName { get; }

        public int HashSize => GetHash().HashSize / 8;

        public void Sign(ReadOnlySpan<byte> source, Span<byte> dest)
        {
            GetHash().TryComputeHash(source, dest, out _);
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

        ~JwtAlgorithmBase()
        {
            Dispose(false);
        }
    }


    public sealed class HMACSHA256Algorithm : JwtAlgorithmBase
    {
        public override string AlgName => "HS256";

        public HMACSHA256Algorithm(byte[] key)
            : base(key)
        {
        }

        protected override HashAlgorithm CreateHashAlgorithm(byte[] key)
        {
            return new HMACSHA256(key);
        }
    }
}