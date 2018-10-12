using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms
{
    /// <summary>
    /// AES Symmetric encryption. The same input will produce a different output each time.
    /// </summary>
    public class Symmetric_AES_CBC
        : Symmetric_AES
    {
        /// <summary>
        /// AES requires a 16-byte IV for CBC.
        /// </summary>
        /// <returns></returns>
        protected override int GetIVSizeBytes()
        {
            return 128 / 8;
        }

        protected override CipherMode GetCipherMode()
        {
            return CipherMode.CBC;
        }
    }
}
