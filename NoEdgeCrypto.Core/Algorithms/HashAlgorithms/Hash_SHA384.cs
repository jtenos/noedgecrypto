using System.IO;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Hash algorithm using SHA384.
    /// </summary>
    public class Hash_SHA384
        : HashAlgorithmBase
    {
        protected override HashResults HashStreamImpl(Stream inputStream)
        {
            using (var sha384 = SHA384.Create())
            {
                return new HashResults(sha384.ComputeHash(inputStream));
            }
        }
    }
}
