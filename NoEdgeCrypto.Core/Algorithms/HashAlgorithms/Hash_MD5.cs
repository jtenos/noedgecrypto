using System.IO;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.HashAlgorithms
{
    /// <summary>
    /// Hash algorithm using MD5.
    /// </summary>
    public class Hash_MD5
        : HashAlgorithmBase
    {
        protected override HashResults HashStreamImpl(Stream inputStream)
        {
            using (var md5 = MD5.Create())
            {
                return new HashResults(md5.ComputeHash(inputStream));
            }
        }
    }
}
