using System.Text;

namespace NoEdgeCrypto.Core.Results
{
    /// <summary>
    /// Wrapper around a byte array for decryption results.
    /// </summary>
    public class DecryptionResults
        : BinaryResults
    {
        /// <summary>
        /// Creates the wrapper around a byte array.
        /// </summary>
        /// <param name="resultingBytes">The bytes that this object represents.</param>
        public DecryptionResults(byte[] resultingBytes)
            : base(resultingBytes)
        {
        }

        /// <summary>
        /// Returns the bytes as a string, when the original plaintext was a string.
        /// </summary>
        /// <param name="encoding">The encoding of the string. Default is UTF8.</param>
        /// <returns>The string representation of the bytes.</returns>
        public string AsString(Encoding encoding = null)
        {
            if (ResultingBytes == null)
            {
                return null;
            }
            encoding = encoding ?? Defaults.Encoding;
            return encoding.GetString(ResultingBytes);
        }

        public static implicit operator byte[](DecryptionResults decryptionResults)
        {
            return decryptionResults.ResultingBytes;
        }
    }
}
