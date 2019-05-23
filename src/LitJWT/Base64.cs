using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LitJWT
{
    internal static unsafe class Base64
    {
        static readonly char[] base64EncodeTable = {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
            'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
            'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
            'w','x','y','z','0','1','2','3','4','5','6','7','8','9','+','/'};

        static readonly char[] base64UrlEncodeTable = {
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
            'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f',
            'g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v',
            'w','x','y','z','0','1','2','3','4','5','6','7','8','9','-','_'}; // 62nd '+' => '-', 63rd '/' => '_'

        // String.Join(", ", Enumerable.Range(0, byte.MaxValue).Select(x => Base64.base64EncodeTable.Cast<char?>().FirstOrDefault(y => x == y) ?? -1))
        static readonly sbyte[] base64DecodeTable = new sbyte[] { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 43, -1, -1, -1, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, -1, -1, -1, -1, -1, -1, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };
        static readonly sbyte[] base64UrlDecodeTable = new sbyte[] { -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 45, -1, -1, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1, -1, -1, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, -1, -1, -1, -1, 95, -1, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 };

        public static int GetMaxBase64Length(int length)
        {
            return (((length + 2) / 3) * 4);
        }

        public static int GetMaxBase64UrlLength(int length)
        {
            return (((length) / 3) * 4);
        }

        public static bool TryToBase64Chars(ReadOnlySpan<byte> bytes, Span<char> chars, out int charsWritten)
        {
            fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
            fixed (char* outChars = &MemoryMarshal.GetReference(chars))
            {
                charsWritten = ConvertBase64Core(inData, outChars, 0, bytes.Length);
                return true;
            }
        }

        static int ConvertBase64Core(byte* bytes, char* chars, int offset, int length)
        {
            var mod3 = length % 3;
            var loopLength = offset + (length - mod3);

            var i = 0;
            var j = 0;

            // use pointer to avoid range check
            fixed (char* table = &base64EncodeTable[0])
            {
                for (i = offset; i < loopLength; i += 3)
                {
                    // 6(2)
                    // 2 + 4(4)
                    // 4 + 2(6)
                    // 6
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    chars[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6)];
                    chars[j + 3] = table[(bytes[i + 2] & 0b00111111)];
                    j += 4;
                }

                i = loopLength;

                if (mod3 == 1)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    chars[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2)];
                    chars[j + 3] = '='; // padding
                    j += 4;
                }
                else if (mod3 == 2)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4)];
                    chars[j + 2] = '=';
                    chars[j + 3] = '=';
                    j += 4;
                }

                return j;
            }
        }

        static int ConvertBase64UrlCore(byte* bytes, char* chars, int offset, int length)
        {
            var mod3 = length % 3;
            var loopLength = offset + (length - mod3);

            var i = 0;
            var j = 0;

            fixed (char* table = &base64EncodeTable[0])
            {
                for (i = offset; i < loopLength; i += 3)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    chars[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6)];
                    chars[j + 3] = table[(bytes[i + 2] & 0b00111111)];
                    j += 4;
                }

                i = loopLength;

                // no-pading '='.
                if (mod3 == 1)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    chars[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2)];
                    j += 3;
                }
                else if (mod3 == 2)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4)];
                    j += 2;
                }

                return j;
            }
        }
    }
}
