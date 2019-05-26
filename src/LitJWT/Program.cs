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

            for (int i = 0; i < 99; i++)
            {
                Span<char> chars = new char[1000];
                Base64.TryToBase64UrlChars(new byte[i], chars, out var actual);
                //i.Should().BeLessOrEqualTo(Base64.GetMaxBase64DecodeLength(actual));
                Console.WriteLine($"{i} should be less or equal to {Base64.GetMaxBase64UrlDecodeLength(actual)}");
            }
        }
    }


    
    
}
