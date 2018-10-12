using System.IO;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Hash algorithm using SHA256.
    /// </summary>
    public class Hash_SHA256
        : HashAlgorithmBase
    {
        protected override HashResults HashStreamImpl(Stream inputStream)
        {
            using (var sha256 = SHA256.Create())
            {
                return new HashResults(sha256.ComputeHash(inputStream));
            }
        }
    }
}
