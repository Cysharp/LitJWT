using FluentAssertions;
using RandomFixtureKit;
using System;
using Xunit;

namespace LitJWT.Tests
{
    public class Base64UrlTest
    {
        static string ReferenceBase64UrlEncode(byte[] input)
        {
            return Convert.ToBase64String(input).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        [Fact]
        public void Base64UrlEncode()
        {
            Span<char> writeTo = new char[1024];
            foreach (var item in FixtureFactory.CreateMany<byte[]>(1000, resolver: RandomByteArrayResolver.Default))
            {
                var reference = ReferenceBase64UrlEncode(item);

                Base64.TryToBase64UrlChars(item, writeTo, out var written);
                var implResult = new string(writeTo.Slice(0, written));

                implResult.Should().Be(reference);
            }
        }

        [Fact]
        public void Base64UrlDecode()
        {
            Span<byte> writeTo = new byte[1024];
            foreach (var item in FixtureFactory.CreateMany<byte[]>(1000, resolver: RandomByteArrayResolver.Default))
            {
                var referenceString = ReferenceBase64UrlEncode(item);

                Base64.TryFromBase64UrlChars(referenceString, writeTo, out var written);
                var implResult = writeTo.Slice(0, written);

                implResult.SequenceEqual(item).Should().BeTrue("Str:[{0}] Reference:{1} Actual:{2}", referenceString, string.Join(",", item), string.Join(",", implResult.ToArray()));
            }
        }

        [Fact]
        public void EdgeCaseEncode()
        {
            Span<char> writeTo = new char[1024];
            foreach (var item in new byte[][] { new byte[0] })
            {
                var reference = ReferenceBase64UrlEncode(item);

                Base64.TryToBase64UrlChars(item, writeTo, out var written);
                var implResult = new string(writeTo.Slice(0, written));

                implResult.Should().Be(reference);
            }
        }

        [Fact]
        public void InvalidDecodeCases()
        {
            Span<byte> writeTo = new byte[1024];
            Base64.TryFromBase64UrlChars("AAB!DEFG", writeTo, out var written).Should().BeFalse();
            Base64.TryFromBase64UrlChars("AAB=DEFG", writeTo, out written).Should().BeFalse();
            Base64.TryFromBase64UrlChars("AABCDEF!", writeTo, out written).Should().BeFalse();
            Base64.TryFromBase64UrlChars("=", writeTo, out written).Should().BeFalse();
            Base64.TryFromBase64UrlChars("A===", writeTo, out written).Should().BeFalse();
            Base64.TryFromBase64UrlChars("A!!!", writeTo, out written).Should().BeFalse();
        }

        [Fact]
        public void EncodeLength()
        {
            for (int i = 0; i < 99; i++)
            {
                Span<char> chars = new char[1000];
                Base64.TryToBase64UrlChars(new byte[i], chars, out var actual);

                actual.Should().Be(Base64.GetBase64UrlEncodeLength(i), "i is " + i);
            }
        }

        [Fact]
        public void DecodeLength()
        {
            for (int i = 0; i < 99; i++)
            {
                Span<char> chars = new char[1000];
                Base64.TryToBase64UrlChars(new byte[i], chars, out var actual);
                i.Should().BeLessOrEqualTo(Base64.GetMaxBase64UrlDecodeLength(actual));
            }
        }

    }
}
