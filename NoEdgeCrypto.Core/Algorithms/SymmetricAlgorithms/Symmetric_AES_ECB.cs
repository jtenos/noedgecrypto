using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms
{
    /// <summary>
    /// Symmetric encryption using AES with ECB - the same input produces the same output,
    /// so this is not recommended for serious encryption.
    /// </summary>
    public class Symmetric_AES_ECB
        : Symmetric_AES
    {
        /// <summary>
        ///  IV is irrelevant in ECB
        /// </summary>
        /// <returns></returns>
        protected override int GetIVSizeBytes()
        {
            return 0;
        }

        protected override CipherMode GetCipherMode()
        {
            return CipherMode.ECB;
        }
    }
}
