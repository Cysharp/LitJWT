using System.Text;

namespace LitJWT
{
    internal class JwtConstants
    {
        public const string Issuer = "iss";
        public const string Subject = "sub";
        public const string Audience = "aud";
        public const string Expiration = "exp";
        public const string NotBefore = "nbf";
        public const string IssuedAt = "iat";
        public const string JwtIdentifier = "jti";
        public const string Algorithm = "alg";
    }

    internal class JwtConstantsUtf8
    {
        public static readonly byte[] Issuer = Encoding.UTF8.GetBytes("iss");
        public static readonly byte[] Subject = Encoding.UTF8.GetBytes("sub");
        public static readonly byte[] Audience = Encoding.UTF8.GetBytes("aud");
        public static readonly byte[] Expiration = Encoding.UTF8.GetBytes("exp");
        public static readonly byte[] NotBefore = Encoding.UTF8.GetBytes("nbf");
        public static readonly byte[] IssuedAt = Encoding.UTF8.GetBytes("iat");
        public static readonly byte[] JwtIdentifier = Encoding.UTF8.GetBytes("jti");
        public static readonly byte[] Algorithm = Encoding.UTF8.GetBytes("alg");
    }
}
