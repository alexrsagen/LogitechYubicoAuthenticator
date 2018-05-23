using System;

namespace YubicoCCID
{
    public class Base32
    {
        /// <summary>
        /// Turns a Base-32 encoded string into raw bytes.
        /// </summary>
        /// <param name="input">Base-32 encoded string</param>
        /// <returns>Returns a byte array of the data represented by <paramref name="input"/>.</returns>
        public static byte[] ToBytes(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentNullException("input");

            input = input.TrimEnd('='); // Remove padding characters
            int byteCount = input.Length * 5 / 8; // This must be TRUNCATED
            byte[] returnArray = new byte[byteCount];

            byte curByte = 0, bitsRemaining = 8;
            int mask = 0, arrayIndex = 0;

            foreach (char c in input)
            {
                int cValue = CharToValue(c);

                if (bitsRemaining > 5)
                {
                    mask = cValue << (bitsRemaining - 5);
                    curByte = (byte)(curByte | mask);
                    bitsRemaining -= 5;
                }
                else
                {
                    mask = cValue >> (5 - bitsRemaining);
                    curByte = (byte)(curByte | mask);
                    returnArray[arrayIndex++] = curByte;
                    curByte = (byte)(cValue << (3 + bitsRemaining));
                    bitsRemaining += 3;
                }
            }

            // If we didn't end with a full byte
            if (arrayIndex != byteCount)
                returnArray[arrayIndex] = curByte;

            return returnArray;
        }

        /// <summary>
        /// Turns raw bytes into a Base-32 encoded string.
        /// </summary>
        /// <param name="input">Raw bytes</param>
        /// <returns>Returns a Base-32 encoded string representing the data in <paramref name="input"/>.</returns>
        public static string ToString(byte[] input)
        {
            if (input == null || input.Length == 0)
                throw new ArgumentNullException("input");

            int charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
            char[] returnArray = new char[charCount];

            byte nextChar = 0, bitsRemaining = 5;
            int arrayIndex = 0;

            foreach (byte b in input)
            {
                nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
                returnArray[arrayIndex++] = ValueToChar(nextChar);

                if (bitsRemaining < 4)
                {
                    nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
                    returnArray[arrayIndex++] = ValueToChar(nextChar);
                    bitsRemaining += 5;
                }

                bitsRemaining -= 3;
                nextChar = (byte)((b << bitsRemaining) & 31);
            }

            // If we didn't end with a full char
            if (arrayIndex != charCount)
            {
                returnArray[arrayIndex++] = ValueToChar(nextChar);
                while (arrayIndex != charCount)
                    returnArray[arrayIndex++] = '='; // Padding
            }

            return new string(returnArray);
        }

        /// <summary>
        /// Turns a Base-32 character into the value represented by it.
        /// </summary>
        /// <param name="c">A single Base-32 character</param>
        /// <returns>Returns the value represented by the character <paramref name="c"/>.</returns>
        private static int CharToValue(char c)
        {
            int value = c;

            // 65-90 == uppercase letters
            if (value < 91 && value > 64)
                return value - 65;

            // 50-55 == numbers 2-7
            if (value < 56 && value > 49)
                return value - 24;

            // 97-122 == lowercase letters
            if (value < 123 && value > 96)
                return value - 97;

            throw new ArgumentException("Character is not a Base32 character.", "c");
        }

        /// <summary>
        /// Turns a single byte into a Base-32 character.
        /// </summary>
        /// <param name="b">A single byte</param>
        /// <returns>Returns the Base-32 character representing the byte <paramref name="b"/>.</returns>
        private static char ValueToChar(byte b)
        {
            if (b < 26)
                return (char)(b + 65);

            if (b < 32)
                return (char)(b + 24);

            throw new ArgumentException("Byte is not a value Base32 value.", "b");
        }

    }
}
