using System;
using System.Linq;
using System.Runtime.InteropServices;

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

        static readonly sbyte[] base64DecodeTable;
        static readonly sbyte[] base64UrlDecodeTable;

        static Base64()
        {
            base64DecodeTable = BuildDecodeTable(base64EncodeTable);
            base64UrlDecodeTable = BuildDecodeTable(base64UrlEncodeTable);
        }

        static sbyte[] BuildDecodeTable(char[] encodeTable)
        {
            var table = encodeTable.Select((x, i) => (x, i)).ToDictionary(x => x.x, x => x.i);
            var array = new sbyte[char.MaxValue];
            for (int i = 0; i < char.MaxValue; i++)
            {
                if (table.TryGetValue((char)i, out var v))
                {
                    array[i] = (sbyte)v;
                }
                else
                {
                    if ((char)i == '=')
                    {
                        array[i] = -2;
                    }
                    else
                    {
                        array[i] = -1;
                    }
                }
            }

            return array;
        }

        public static int GetBase64EncodeLength(int length)
        {
            if (length == 0) return 0;
            var v = (((length + 2) / 3) * 4);
            return v == 0 ? 4 : v;
        }

        public static int GetBase64UrlEncodeLength(int length)
        {
            if (length == 0) return 0;
            var mod = (length % 3);
            return ((length / 3) * 4) + ((mod == 0) ? 0 : (mod + 1));
        }


        public static int GetMaxBase64DecodeLength(int length)
        {
            return (length / 4) * 3;
        }

        public static int GetMaxBase64UrlDecodeLength(int length)
        {
            if (length == 0) return 0;
            var mod = length % 4;
            return (length / 4) * 3 + mod;
        }

        public static bool TryFromBase64String(string s, Span<byte> bytes, out int bytesWritten)
        {
            return TryFromBase64Chars(s.AsSpan(), bytes, out bytesWritten);
        }

        public static bool TryFromBase64Chars(ReadOnlySpan<char> chars, Span<byte> bytes, out int bytesWritten)
        {
            fixed (char* inChars = &MemoryMarshal.GetReference(chars))
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes))
            {
                return DecodeBase64Core(inChars, outData, 0, chars.Length, base64DecodeTable, true, out bytesWritten);
            }
        }

        public static bool TryFromBase64UrlString(string s, Span<byte> bytes, out int bytesWritten)
        {
            return TryFromBase64UrlChars(s.AsSpan(), bytes, out bytesWritten);
        }

        public static bool TryFromBase64UrlChars(ReadOnlySpan<char> chars, Span<byte> bytes, out int bytesWritten)
        {
            fixed (char* inChars = &MemoryMarshal.GetReference(chars))
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes))
            {
                return DecodeBase64Core(inChars, outData, 0, chars.Length, base64UrlDecodeTable, false, out bytesWritten);
            }
        }

        // TODO:TryEncodeToUtf8
        public static bool TryEncodeBase64(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
        {
            throw new NotImplementedException();
        }

        public static bool TryEncodeBase64Url(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
        {
            //TODO:
            Span<char> buffer = stackalloc char[utf8.Length];
            TryToBase64UrlChars(bytes, buffer, out bytesWritten);
            for (int i = 0; i < buffer.Length; i++)
            {
                utf8[i] = (byte)buffer[i];
            }
            return true;
        }

        public static bool TryToBase64Chars(ReadOnlySpan<byte> bytes, Span<char> chars, out int charsWritten)
        {
            fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
            fixed (char* outChars = &MemoryMarshal.GetReference(chars))
            {
                charsWritten = EncodeBase64Core(inData, outChars, 0, bytes.Length, base64EncodeTable, true);
                return true;
            }
        }

        public static bool TryToBase64UrlChars(ReadOnlySpan<byte> bytes, Span<char> chars, out int charsWritten)
        {
            fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
            fixed (char* outChars = &MemoryMarshal.GetReference(chars))
            {
                charsWritten = EncodeBase64Core(inData, outChars, 0, bytes.Length, base64UrlEncodeTable, false);
                return true;
            }
        }

        static int EncodeBase64Core(byte* bytes, char* chars, int offset, int length, char[] encodeTable, bool withPadding)
        {
            var mod3 = length % 3;
            var loopLength = offset + (length - mod3);

            var i = 0;
            var j = 0;

            // use pointer to avoid range check
            fixed (char* table = &encodeTable[0])
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

                if (mod3 == 2)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    chars[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2)];
                    if (withPadding)
                    {
                        chars[j + 3] = '='; // padding
                        j += 4;
                    }
                    else
                    {
                        j += 3;
                    }
                }
                else if (mod3 == 1)
                {
                    chars[j] = table[(bytes[i] & 0b11111100) >> 2];
                    chars[j + 1] = table[((bytes[i] & 0b00000011) << 4)];
                    if (withPadding)
                    {
                        chars[j + 2] = '=';
                        chars[j + 3] = '=';
                        j += 4;
                    }
                    else
                    {
                        j += 2;
                    }
                }

                return j;
            }
        }

        static bool DecodeBase64Core(char* inChars, byte* outData, int offset, int length, sbyte[] decodeTable, bool withPadding, out int written)
        {
            if (length == 0)
            {
                written = 0;
                return true;
            }

            var loopLength = offset + length - 4; // skip last-chunk

            var i = 0;
            var j = 0;
            fixed (sbyte* table = &decodeTable[0])
            {
                for (i = offset; i < loopLength;)
                {
                    ref var i0 = ref table[inChars[i]];
                    ref var i1 = ref table[inChars[i + 1]];
                    ref var i2 = ref table[inChars[i + 2]];
                    ref var i3 = ref table[inChars[i + 3]];

#pragma warning disable CS0675
                    if (((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000)
                    {
                        written = 0;
                        return false;
                    }
#pragma warning restore CS0675

                    // 6 + 2(4)
                    // 4 + 4(2)
                    // 2 + 6
                    var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                    var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                    var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));

                    outData[j] = r0;
                    outData[j + 1] = r1;
                    outData[j + 2] = r2;

                    i += 4;
                    j += 3;
                }

                var rest = length - i;
                if (withPadding)
                {
                    // Base64
                    if (rest != 4)
                    {
                        written = 0;
                        return false;
                    }

                    {
                        ref var i0 = ref table[inChars[i]];
                        ref var i1 = ref table[inChars[i + 1]];
                        ref var i2 = ref table[inChars[i + 2]];
                        ref var i3 = ref table[inChars[i + 3]];

                        if (i3 == -2)
                        {
                            if (i2 == -2)
                            {
                                if (i1 == -2)
                                {
                                    if (i0 == -2)
                                    {
                                        // ====
                                    }

                                    // *===
                                    written = 0;
                                    return false;
                                }

                                {
                                    // **==
                                    if (IsInvalid(ref i0, ref i1))
                                    {
                                        written = 0;
                                        return false;
                                    }

                                    var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                                    outData[j] = r0;
                                    j += 1;
                                    written = j;
                                    return true;
                                }
                            }

                            {
                                // ***=
                                if (IsInvalid(ref i0, ref i1, ref i2))
                                {
                                    written = 0;
                                    return false;
                                }

                                var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                                var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                                outData[j] = r0;
                                outData[j + 1] = r1;
                                j += 2;
                                written = j;
                                return true;
                            }
                        }
                        else
                        {
                            // ****
                            if (IsInvalid(ref i0, ref i1, ref i2, ref i3))
                            {
                                written = 0;
                                return false;
                            }

                            var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                            var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                            var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));
                            outData[j] = r0;
                            outData[j + 1] = r1;
                            outData[j + 2] = r2;
                            j += 3;
                            written = j;
                            return true;
                        }
                    }
                }
                else
                {
                    // Base64url
                    if (rest == 4)
                    {
                        ref var i0 = ref table[inChars[i]];
                        ref var i1 = ref table[inChars[i + 1]];
                        ref var i2 = ref table[inChars[i + 2]];
                        ref var i3 = ref table[inChars[i + 3]];
                        if (IsInvalid(ref i0, ref i1, ref i2, ref i3))
                        {
                            written = 0;
                            return false;
                        }
                        var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                        var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                        var r2 = (byte)(((i2 & 0b00000011) << 6) | (i3 & 0b00111111));
                        outData[j] = r0;
                        outData[j + 1] = r1;
                        outData[j + 2] = r2;
                        j += 3;
                        written = j;
                        return true;
                    }
                    else if (rest == 3)
                    {
                        ref var i0 = ref table[inChars[i]];
                        ref var i1 = ref table[inChars[i + 1]];
                        ref var i2 = ref table[inChars[i + 2]];
                        if (IsInvalid(ref i0, ref i1, ref i2))
                        {
                            written = 0;
                            return false;
                        }
                        var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                        var r1 = (byte)(((i1 & 0b00001111) << 4) | ((i2 & 0b00111100) >> 2));
                        outData[j] = r0;
                        outData[j + 1] = r1;
                        j += 2;
                        written = j;
                        return true;
                    }
                    else if (rest == 2)
                    {
                        ref var i0 = ref table[inChars[i]];
                        ref var i1 = ref table[inChars[i + 1]];
                        if (IsInvalid(ref i0, ref i1))
                        {
                            written = 0;
                            return false;
                        }
                        var r0 = (byte)(((i0 & 0b00111111) << 2) | ((i1 & 0b00110000) >> 4));
                        outData[j] = r0;
                        j += 1;
                        written = j;
                        return true;
                    }
                    else
                    {
                        ref var i0 = ref table[inChars[i]];
                        if (IsInvalid(ref i0))
                        {
                            written = 0;
                            return false;
                        }
                        var r0 = (byte)(((i0 & 0b00111111) << 2));
                        outData[j] = r0;
                        j += 1;
                        written = j;
                        return true;
                    }
                }
            }
        }

#pragma warning disable CS0675


        static bool IsInvalid(ref sbyte i0)
        {
            if (((i0) & 0b10000000) == 0b10000000)
            {
                return true;
            }

            return false;
        }


        static bool IsInvalid(ref sbyte i0, ref sbyte i1)
        {
            if (((i0 | i1) & 0b10000000) == 0b10000000)
            {
                return true;
            }

            return false;
        }


        static bool IsInvalid(ref sbyte i0, ref sbyte i1, ref sbyte i2)
        {
            if (((i0 | i1 | i2) & 0b10000000) == 0b10000000)
            {
                return true;
            }

            return false;
        }

        static bool IsInvalid(ref sbyte i0, ref sbyte i1, ref sbyte i2, ref sbyte i3)
        {
            if (((i0 | i1 | i2 | i3) & 0b10000000) == 0b10000000)
            {
                return true;
            }

            return false;
        }

#pragma warning restore CS0675

    }
}
