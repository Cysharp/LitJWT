using System;
using System.Buffers;
using System.Linq;
using System.Runtime.InteropServices;

namespace LitJWT
{
    public static unsafe class Base64
    {
        // char table

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

        // utf8 encode table(decode-table can use same)

        static readonly byte[] base64Utf8EncodeTable = {
            (byte)'A',(byte)'B',(byte)'C',(byte)'D',(byte)'E',(byte)'F',(byte)'G',(byte)'H',(byte)'I',(byte)'J',(byte)'K',(byte)'L',(byte)'M',(byte)'N',(byte)'O',(byte)'P',
            (byte)'Q',(byte)'R',(byte)'S',(byte)'T',(byte)'U',(byte)'V',(byte)'W',(byte)'X',(byte)'Y',(byte)'Z',(byte)'a',(byte)'b',(byte)'c',(byte)'d',(byte)'e',(byte)'f',
            (byte)'g',(byte)'h',(byte)'i',(byte)'j',(byte)'k',(byte)'l',(byte)'m',(byte)'n',(byte)'o',(byte)'p',(byte)'q',(byte)'r',(byte)'s',(byte)'t',(byte)'u',(byte)'v',
            (byte)'w',(byte)'x',(byte)'y',(byte)'z',(byte)'0',(byte)'1',(byte)'2',(byte)'3',(byte)'4',(byte)'5',(byte)'6',(byte)'7',(byte)'8',(byte)'9',(byte)'+',(byte)'/'};

        static readonly byte[] base64UrlUtf8EncodeTable = {
            (byte)'A',(byte)'B',(byte)'C',(byte)'D',(byte)'E',(byte)'F',(byte)'G',(byte)'H',(byte)'I',(byte)'J',(byte)'K',(byte)'L',(byte)'M',(byte)'N',(byte)'O',(byte)'P',
            (byte)'Q',(byte)'R',(byte)'S',(byte)'T',(byte)'U',(byte)'V',(byte)'W',(byte)'X',(byte)'Y',(byte)'Z',(byte)'a',(byte)'b',(byte)'c',(byte)'d',(byte)'e',(byte)'f',
            (byte)'g',(byte)'h',(byte)'i',(byte)'j',(byte)'k',(byte)'l',(byte)'m',(byte)'n',(byte)'o',(byte)'p',(byte)'q',(byte)'r',(byte)'s',(byte)'t',(byte)'u',(byte)'v',
            (byte)'w',(byte)'x',(byte)'y',(byte)'z',(byte)'0',(byte)'1',(byte)'2',(byte)'3',(byte)'4',(byte)'5',(byte)'6',(byte)'7',(byte)'8',(byte)'9',(byte)'-',(byte)'_'};


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

        public static bool TryFromBase64Utf8(ReadOnlySpan<byte> utf8, Span<byte> bytes, out int bytesWritten)
        {
            fixed (byte* inChars = &MemoryMarshal.GetReference(utf8))
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes))
            {
                return DecodeBase64Core(inChars, outData, 0, utf8.Length, base64DecodeTable, true, out bytesWritten);
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

        public static bool TryFromBase64UrlUtf8(ReadOnlySpan<byte> utf8, Span<byte> bytes, out int bytesWritten)
        {
            fixed (byte* inChars = &MemoryMarshal.GetReference(utf8))
            fixed (byte* outData = &MemoryMarshal.GetReference(bytes))
            {
                return DecodeBase64Core(inChars, outData, 0, utf8.Length, base64UrlDecodeTable, false, out bytesWritten);
            }
        }

        public static bool TryToBase64Utf8(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
        {
            fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
            fixed (byte* outBytes = &MemoryMarshal.GetReference(utf8))
            {
                bytesWritten = EncodeBase64Core(inData, outBytes, 0, bytes.Length, base64Utf8EncodeTable, true);
                return true;
            }
        }

        public static bool TryToBase64UrlUtf8(ReadOnlySpan<byte> bytes, Span<byte> utf8, out int bytesWritten)
        {
            fixed (byte* inData = &MemoryMarshal.GetReference(bytes))
            fixed (byte* outBytes = &MemoryMarshal.GetReference(utf8))
            {
                bytesWritten = EncodeBase64Core(inData, outBytes, 0, bytes.Length, base64UrlUtf8EncodeTable, false);
                return true;
            }
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

        public static string EncodeToBase64UrlString(byte[] bytes)
        {
            var buffer = ArrayPool<char>.Shared.Rent(GetBase64UrlEncodeLength(bytes.Length));
            try
            {
                var bufferSpan = buffer.AsSpan();
                TryToBase64UrlChars(bytes, bufferSpan, out var written);
                return new string(bufferSpan.Slice(0, written));
            }
            finally
            {
                ArrayPool<char>.Shared.Return(buffer);
            }
        }

        public static string EncodeToBase64String(byte[] bytes)
        {
            var buffer = ArrayPool<char>.Shared.Rent(GetBase64EncodeLength(bytes.Length));
            try
            {
                var bufferSpan = buffer.AsSpan();
                TryToBase64Chars(bytes, bufferSpan, out var written);
                return new string(bufferSpan.Slice(0, written));
            }
            finally
            {
                ArrayPool<char>.Shared.Return(buffer);
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

        static int EncodeBase64Core(byte* bytes, byte* outBytes, int offset, int length, byte[] encodeTable, bool withPadding)
        {
            var mod3 = length % 3;
            var loopLength = offset + (length - mod3);

            var i = 0;
            var j = 0;

            // use pointer to avoid range check
            fixed (byte* table = &encodeTable[0])
            {
                for (i = offset; i < loopLength; i += 3)
                {
                    // 6(2)
                    // 2 + 4(4)
                    // 4 + 2(6)
                    // 6
                    outBytes[j] = table[(bytes[i] & 0b11111100) >> 2];
                    outBytes[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    outBytes[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2) | ((bytes[i + 2] & 0b11000000) >> 6)];
                    outBytes[j + 3] = table[(bytes[i + 2] & 0b00111111)];
                    j += 4;
                }

                i = loopLength;

                if (mod3 == 2)
                {
                    outBytes[j] = table[(bytes[i] & 0b11111100) >> 2];
                    outBytes[j + 1] = table[((bytes[i] & 0b00000011) << 4) | ((bytes[i + 1] & 0b11110000) >> 4)];
                    outBytes[j + 2] = table[((bytes[i + 1] & 0b00001111) << 2)];
                    if (withPadding)
                    {
                        outBytes[j + 3] = (byte)'='; // padding
                        j += 4;
                    }
                    else
                    {
                        j += 3;
                    }
                }
                else if (mod3 == 1)
                {
                    outBytes[j] = table[(bytes[i] & 0b11111100) >> 2];
                    outBytes[j + 1] = table[((bytes[i] & 0b00000011) << 4)];
                    if (withPadding)
                    {
                        outBytes[j + 2] = (byte)'=';
                        outBytes[j + 3] = (byte)'=';
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

        static bool DecodeBase64Core(byte* inChars, byte* outData, int offset, int length, sbyte[] decodeTable, bool withPadding, out int written)
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
