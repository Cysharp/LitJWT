using System;
using System.Runtime.CompilerServices;

namespace LitJWT
{
    /// <summary>
    /// zero-allocate itoa, dtoa, atoi, atod converters.
    /// </summary>
    internal static class NumberConverter
    {
        /// <summary>
        /// 0 ~ 9
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNumber(byte c)
        {
            return (byte)'0' <= c && c <= (byte)'9';
        }

        /// <summary>
        /// Is 0 ~ 9, '.', '+', '-'?
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNumberRepresentation(byte c)
        {
            switch (c)
            {
                case 43: // +
                case 45: // -
                case 46: // .
                case 48: // 0
                case 49:
                case 50:
                case 51:
                case 52:
                case 53:
                case 54:
                case 55:
                case 56:
                case 57: // 9
                    return true;
                case 44:
                case 47:
                default:
                    return false;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ReadInt32(byte[] bytes, int offset, out int readCount)
        {
            return checked((int)ReadInt64(bytes, offset, out readCount));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ReadInt64(ReadOnlySpan<byte> bytes, int offset, out int readCount)
        {
            var value = 0L;
            var sign = 1;

            if (bytes[offset] == '-')
            {
                sign = -1;
            }

            for (int i = ((sign == -1) ? offset + 1 : offset); i < bytes.Length; i++)
            {
                if (!IsNumber(bytes[i]))
                {
                    readCount = i - offset;
                    goto END;
                }

                // long.MinValue causes overflow so use unchecked.
                value = unchecked(value * 10 + (bytes[i] - '0'));
            }
            readCount = bytes.Length - offset;

            END:
            return unchecked(value * sign);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int WriteInt32(Span<byte> buffer, int offset, int value)
        {
            return WriteInt64(buffer, offset, (long)value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int WriteInt64(Span<byte> buffer, int offset, long value)
        {
            var startOffset = offset;

            long num1 = value, num2, num3, num4, num5, div;

            if (value < 0)
            {
                if (value == long.MinValue) // -9223372036854775808
                {
                    buffer[offset++] = (byte)'-';
                    buffer[offset++] = (byte)'9';
                    buffer[offset++] = (byte)'2';
                    buffer[offset++] = (byte)'2';
                    buffer[offset++] = (byte)'3';
                    buffer[offset++] = (byte)'3';
                    buffer[offset++] = (byte)'7';
                    buffer[offset++] = (byte)'2';
                    buffer[offset++] = (byte)'0';
                    buffer[offset++] = (byte)'3';
                    buffer[offset++] = (byte)'6';
                    buffer[offset++] = (byte)'8';
                    buffer[offset++] = (byte)'5';
                    buffer[offset++] = (byte)'4';
                    buffer[offset++] = (byte)'7';
                    buffer[offset++] = (byte)'7';
                    buffer[offset++] = (byte)'5';
                    buffer[offset++] = (byte)'8';
                    buffer[offset++] = (byte)'0';
                    buffer[offset++] = (byte)'8';
                    return offset - startOffset;
                }

                buffer[offset++] = (byte)'-';
                num1 = unchecked(-value);
            }

            // WriteUInt64(inlined)

            if (num1 < 10000)
            {
                if (num1 < 10) { goto L1; }
                if (num1 < 100) { goto L2; }
                if (num1 < 1000) { goto L3; }
                goto L4;
            }
            else
            {
                num2 = num1 / 10000;
                num1 -= num2 * 10000;
                if (num2 < 10000)
                {
                    if (num2 < 10) { goto L5; }
                    if (num2 < 100) { goto L6; }
                    if (num2 < 1000) { goto L7; }
                    goto L8;
                }
                else
                {
                    num3 = num2 / 10000;
                    num2 -= num3 * 10000;
                    if (num3 < 10000)
                    {
                        if (num3 < 10) { goto L9; }
                        if (num3 < 100) { goto L10; }
                        if (num3 < 1000) { goto L11; }
                        goto L12;
                    }
                    else
                    {
                        num4 = num3 / 10000;
                        num3 -= num4 * 10000;
                        if (num4 < 10000)
                        {
                            if (num4 < 10) { goto L13; }
                            if (num4 < 100) { goto L14; }
                            if (num4 < 1000) { goto L15; }
                            goto L16;
                        }
                        else
                        {
                            num5 = num4 / 10000;
                            num4 -= num5 * 10000;
                            if (num5 < 10000)
                            {
                                if (num5 < 10) { goto L17; }
                                if (num5 < 100) { goto L18; }
                                if (num5 < 1000) { goto L19; }
                                goto L20;
                            }
                            L20:
                            buffer[offset++] = (byte)('0' + (div = (num5 * 8389L) >> 23));
                            num5 -= div * 1000;
                            L19:
                            buffer[offset++] = (byte)('0' + (div = (num5 * 5243L) >> 19));
                            num5 -= div * 100;
                            L18:
                            buffer[offset++] = (byte)('0' + (div = (num5 * 6554L) >> 16));
                            num5 -= div * 10;
                            L17:
                            buffer[offset++] = (byte)('0' + (num5));
                        }
                        L16:
                        buffer[offset++] = (byte)('0' + (div = (num4 * 8389L) >> 23));
                        num4 -= div * 1000;
                        L15:
                        buffer[offset++] = (byte)('0' + (div = (num4 * 5243L) >> 19));
                        num4 -= div * 100;
                        L14:
                        buffer[offset++] = (byte)('0' + (div = (num4 * 6554L) >> 16));
                        num4 -= div * 10;
                        L13:
                        buffer[offset++] = (byte)('0' + (num4));
                    }
                    L12:
                    buffer[offset++] = (byte)('0' + (div = (num3 * 8389L) >> 23));
                    num3 -= div * 1000;
                    L11:
                    buffer[offset++] = (byte)('0' + (div = (num3 * 5243L) >> 19));
                    num3 -= div * 100;
                    L10:
                    buffer[offset++] = (byte)('0' + (div = (num3 * 6554L) >> 16));
                    num3 -= div * 10;
                    L9:
                    buffer[offset++] = (byte)('0' + (num3));
                }
                L8:
                buffer[offset++] = (byte)('0' + (div = (num2 * 8389L) >> 23));
                num2 -= div * 1000;
                L7:
                buffer[offset++] = (byte)('0' + (div = (num2 * 5243L) >> 19));
                num2 -= div * 100;
                L6:
                buffer[offset++] = (byte)('0' + (div = (num2 * 6554L) >> 16));
                num2 -= div * 10;
                L5:
                buffer[offset++] = (byte)('0' + (num2));
            }
            L4:
            buffer[offset++] = (byte)('0' + (div = (num1 * 8389L) >> 23));
            num1 -= div * 1000;
            L3:
            buffer[offset++] = (byte)('0' + (div = (num1 * 5243L) >> 19));
            num1 -= div * 100;
            L2:
            buffer[offset++] = (byte)('0' + (div = (num1 * 6554L) >> 16));
            num1 -= div * 10;
            L1:
            buffer[offset++] = (byte)('0' + (num1));

            return offset - startOffset;
        }
    }
}