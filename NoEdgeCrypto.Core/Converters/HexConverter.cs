using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace NoEdgeCrypto.Core.Converters
{
    /// <summary>
    /// Methods for converting byte arrays to/from hex.
    /// </summary>
    public static class HexConverter
    {
        private static readonly char[] _validHexChars = { 
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
            'a', 'A', 'b', 'B', 'c', 'C', 'd', 'D', 'e', 'E', 'f', 'F'
        };

        /// <summary>
        /// Converts a byte array to hex.
        /// </summary>
        /// <param name="input">The byte array.</param>
        /// <param name="delimiter">The delimiter between bytes. For no delimiter, use null. Default is null.</param>
        /// <param name="upperCase">True if the hex should be in upper-case. Default is true.</param>
        /// <returns>The hex output.</returns>
        public static string BytesToHex(IEnumerable<byte> input, char? delimiter = null, bool upperCase = true)
        {
            if (input == null)
            {
                return null;
            }

            bool isFirst = true;
            var sb = new StringBuilder();
            foreach (byte b in input)
            {
                if (!isFirst && delimiter.HasValue)
                {
                    sb.Append(delimiter);
                }
                sb.AppendFormat(b.ToString(upperCase ? "X2" : "x2"));
                isFirst = false;
            }
            return sb.ToString();
        }

        /// <summary>
        /// Converts a hex string to a byte array.
        /// </summary>
        /// <param name="input">The hex input. This can be upper or lower case, and can contain a
        /// one-character delimiter between each hex byte, or not.</param>
        /// <returns></returns>
        public static byte[] HexToBytes(string input)
        {
            if (input == null)
            {
                return null;
            }
            char? delimiter;
            var nonHexChars = input.Where(c => !_validHexChars.Contains(c)).Distinct().ToArray();
            if (!nonHexChars.Any())
            {
                delimiter = null;
            }
            else if (nonHexChars.Length == 1)
            {
                delimiter = nonHexChars[0];
            }
            else
            {
                throw new ArgumentException("input must contain only hex characters and zero or one delimiters.");
            }

            if (input == null)
            {
                return null;
            }

            byte[] result;
            if (delimiter.HasValue)
            {
                string[] fields = input.Split(delimiter.Value);
                result = new byte[fields.Length];
                for (int i = 0; i < fields.Length; ++i)
                {
                    result[i] = ToByte(fields[i]);
                }
            }
            else
            {
                result = new byte[input.Length / 2];
                for (int i = 0; i < input.Length / 2; ++i)
                {
                    result[i] = ToByte(input.Substring((2 * i), 2));
                }
            }

            return result;
        }

        private static byte ToByte(string x2)
        {
            return (byte)Convert.ToInt32(x2, 16);
        }
    }
}
