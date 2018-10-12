using System.IO;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Hash algorithm using SHA1.
    /// </summary>
    public class Hash_SHA1
        : HashAlgorithmBase
    {
        protected override HashResults HashStreamImpl(Stream inputStream)
        {
            using (var sha1 = SHA1.Create())
            {
                return new HashResults(sha1.ComputeHash(inputStream));
            }
        }
    }
}
