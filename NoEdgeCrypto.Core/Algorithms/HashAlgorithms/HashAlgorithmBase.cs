using System.IO;
using System.Text;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Base class for hash algorithms.
    /// </summary>
    public abstract class HashAlgorithmBase
    {
        /// <summary>
        /// Hashes a stream using this algorithm.
        /// </summary>
        /// <param name="inputStream">The stream whose contents will be hashed.</param>
        /// <returns>The hash, as a HashResults object.</returns>
        public HashResults HashStream(Stream inputStream)
        {
            if (inputStream == null)
            {
                return new HashResults(null);
            }
            return HashStreamImpl(inputStream);
        }

        protected abstract HashResults HashStreamImpl(Stream inputStream);

        /// <summary>
        /// Hashes a string using this algorithm.
        /// </summary>
        /// <param name="input">The string which will be hashed.</param>
        /// <param name="encoding">The encoding on the string - default is UTF8.</param>
        /// <returns>The hash, as a HashResults object.</returns>
        public HashResults HashString(string input, Encoding encoding = null)
        {
            encoding = encoding ?? Defaults.Encoding;
            return HashBytes(encoding.GetBytes(input));
        }

        /// <summary>
        /// Hashes a byte array using this algorithm.
        /// </summary>
        /// <param name="input">The bytes which will be hashed.</param>
        /// <returns>The hash, as a HashResults object.</returns>
        public HashResults HashBytes(byte[] input)
        {
            using (var inputStream = new MemoryStream(input))
            {
                return new HashResults(HashStream(inputStream));
            }
        }
    }
}
