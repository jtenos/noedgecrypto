using System.IO;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Hash algorith using SHA512.
    /// </summary>
    public class Hash_SHA512
        : HashAlgorithmBase
    {
        protected override HashResults HashStreamImpl(Stream inputStream)
        {
            using (var sha512 = SHA512.Create())
            {
                return new HashResults(sha512.ComputeHash(inputStream));
            }
        }
    }
}
