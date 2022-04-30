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
        public static bool IsNumber(byte c) => c >= NumericByte.Zero && c <= NumericByte.Nine;

        /// <summary>
        /// Is 0 ~ 9, '.', '+', '-'?
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool IsNumberRepresentation(byte c)
        {
            switch (c)
            {
                case NumericByte.Plus:
                case NumericByte.Minus:
                case NumericByte.Dot:
                    return true;
                default:
                    return IsNumber(c);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int ReadInt32(byte[] bytes, int offset, out int readCount) => checked((int)ReadInt64(bytes, offset, out readCount));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static long ReadInt64(ReadOnlySpan<byte> bytes, int offset, out int readCount)
        {
            var value = 0L;
            var sign = 1;

            if (bytes[offset] == NumericByte.Minus)
            {
                sign = -1;
                ++offset;
            }

            var offsetCounter = 0;

            for (int i = offset; i < bytes.Length; i++)
            {
                if (!IsNumber(bytes[i]))
                {
                    offsetCounter = i - offset;
                    break;
                }

                // long.MinValue causes overflow so use unchecked.
                value = unchecked(value * 10 + (bytes[i] - NumericByte.Zero));
            }

            readCount = offsetCounter > 0 ? offsetCounter : bytes.Length - offset;

            return unchecked(value * sign);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int WriteInt32(Span<byte> buffer, int offset, int value) => WriteInt64(buffer, offset, value);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int WriteInt64(Span<byte> buffer, int offset, long value)
        {
            var startOffset = offset;

            long num1 = value;

            if (value < 0)
            {
                if (value == long.MinValue)
                {
                    buffer[offset++] = NumericByte.Minus;
                    buffer[offset++] = NumericByte.Nine;
                    buffer[offset++] = NumericByte.Two;
                    buffer[offset++] = NumericByte.Two;
                    buffer[offset++] = NumericByte.Three;
                    buffer[offset++] = NumericByte.Three;
                    buffer[offset++] = NumericByte.Seven;
                    buffer[offset++] = NumericByte.Two;
                    buffer[offset++] = NumericByte.Zero;
                    buffer[offset++] = NumericByte.Three;
                    buffer[offset++] = NumericByte.Six;
                    buffer[offset++] = NumericByte.Eight;
                    buffer[offset++] = NumericByte.Five;
                    buffer[offset++] = NumericByte.Four;
                    buffer[offset++] = NumericByte.Seven;
                    buffer[offset++] = NumericByte.Seven;
                    buffer[offset++] = NumericByte.Five;
                    buffer[offset++] = NumericByte.Eight;
                    buffer[offset++] = NumericByte.Zero;
                    buffer[offset++] = NumericByte.Eight;
                    return offset - startOffset;
                }

                buffer[offset++] = NumericByte.Minus;
                num1 = unchecked(-value);
            }

            SetNumber(ref num1, buffer, ref offset, out long num2);

            SetNumber(ref num2, buffer, ref offset, out long num3);

            SetNumber(ref num3, buffer, ref offset, out long num4);

            SetNumber(ref num4, buffer, ref offset, out long num5);

            SetNumber(ref num5, buffer, ref offset, out _);

            if (num5 != 0)
                SetBytesByStage(ref num4, buffer, ref offset);

            if (num4 != 0)
                SetBytesByStage(ref num3, buffer, ref offset);

            if (num3 != 0)
                SetBytesByStage(ref num2, buffer, ref offset);

            if (num2 != 0)
                SetBytesByStage(ref num1, buffer, ref offset);

            return offset - startOffset;
        }

        /// <summary>
        /// Helper method that would write bytes to the buffer 
        /// used for <see cref="WriteInt64(Span{byte}, int, long)"/>
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="number"></param>
        /// <param name="multiplier"></param>
        /// <param name="bitwise"></param>
        /// <param name="base10"></param>
        private static void WriteBytes(ref long number, Span<byte> buffer, ref int offset, long multiplier, int bitwise, int base10)
        {
            long div = (number * multiplier) >> bitwise;
            number -= div * base10;
            buffer[offset++] = (byte)('0' + div);
        }

        /// <summary>
        /// Helper method that would use <see cref="WriteBytes(ref long, Span{byte}, ref int, long, int, int)"/> to write bytes to the buffer
        /// based on a case. 
        /// used for <see cref="WriteInt64(Span{byte}, int, long)"/>
        /// </summary>
        /// <param name="number"></param>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="stage"></param>
        private static void SetBytesByStage(ref long number, Span<byte> buffer, ref int offset, int stage = 4)
        {
            if (number == 0) return;

            switch (stage)
            {
                case 1:
                    break;
                case 2:
                    WriteBytes(ref number, buffer, ref offset, 6554L, 16, 10);
                    break;
                case 3:
                    WriteBytes(ref number, buffer, ref offset, 5243L, 19, 100);
                    WriteBytes(ref number, buffer, ref offset, 6554L, 16, 10);
                    break;
                case 4:
                    WriteBytes(ref number, buffer, ref offset, 8389L, 23, 1000);
                    WriteBytes(ref number, buffer, ref offset, 5243L, 19, 100);
                    WriteBytes(ref number, buffer, ref offset, 6554L, 16, 10);
                    break;
            }

            buffer[offset++] = (byte)('0' + number);
        }

        /// <summary>
        /// Helper method in conjection of <see cref="SetBytesByStage(ref long, Span{byte}, ref int, int)"/>
        /// To apply the number rules and output the next number.
        /// used for <see cref="WriteInt64(Span{byte}, int, long)"/>
        /// </summary>
        /// <param name="number"></param>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="nextNumber"></param>
        private static void SetNumber(ref long number, Span<byte> buffer, ref int offset, out long nextNumber)
        {
            nextNumber = 0;
            if (number > 0)
            {
                if (number < 10000)
                {
                    if (number < 10)
                        SetBytesByStage(ref number, buffer, ref offset, 1);
                    else if (number < 100)
                        SetBytesByStage(ref number, buffer, ref offset, 2);
                    else if (number < 1000)
                        SetBytesByStage(ref number, buffer, ref offset, 3);
                    else
                        SetBytesByStage(ref number, buffer, ref offset, 4);
                }
                else
                {
                    nextNumber = number / 10000;
                    number %= 10000;
                }
            }
        }
    }
}