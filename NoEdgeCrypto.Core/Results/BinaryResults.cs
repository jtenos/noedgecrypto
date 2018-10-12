using System;
using NoEdgeCrypto.Core.Converters;

namespace NoEdgeCrypto.Core.Results
{
    /// <summary>
    /// A wrapper around a byte array, with methods for retrieving the bytes, or various string formats.
    /// </summary>
    public abstract class BinaryResults
    {
        private readonly byte[] _resultingBytes;

        protected byte[] ResultingBytes { get { return _resultingBytes; } }

        protected BinaryResults(byte[] resultingBytes)
        {
            _resultingBytes = resultingBytes;
        }

        /// <summary>
        /// Returns the raw bytes in the result.
        /// </summary>
        /// <returns>The byte array.</returns>
        public byte[] AsBytes()
        {
            return ResultingBytes;
        }

        /// <summary>
        /// Converts the raw bytes to Base64.
        /// </summary>
        /// <returns>The base64 string.</returns>
        public string AsBase64()
        {
            if (ResultingBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(ResultingBytes);
        }

        /// <summary>
        /// Converts the raw bytes to ASCII85.
        /// </summary>
        /// <returns>The ASCII85 string.</returns>
        public string AsAscii85()
        {
            if (ResultingBytes == null)
            {
                return null;
            }
            return Ascii85Converter.BytesToAscii85(ResultingBytes);
        }

        /// <summary>
        /// Returns the raw bytes as hex.
        /// </summary>
        /// <param name="upper">True if the results should be upper case. Default is true.</param>
        /// <param name="delimiter">The delimiter between hex bytes. Default is null.</param>
        /// <returns>The hex string.</returns>
        public string AsHex(bool upper = true, char? delimiter = null)
        {
            if (ResultingBytes == null)
            {
                return null;
            }
            return HexConverter.BytesToHex(ResultingBytes, delimiter, upper);
        }

        /// <summary>
        /// Returns the byte array as Base64.
        /// </summary>
        /// <returns>The base64 string.</returns>
        public override string ToString()
        {
            return AsBase64();
        }

        public static implicit operator byte[](BinaryResults binaryResults)
        {
            return binaryResults.AsBytes();
        }
    }
}
