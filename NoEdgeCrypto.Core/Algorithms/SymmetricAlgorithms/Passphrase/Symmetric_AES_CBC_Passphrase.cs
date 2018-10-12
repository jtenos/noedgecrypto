using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase
{
    /// <summary>
    /// AES Symmetric encryption. A 256-bit key is generated using PBKDF2 with 16384 iterations, and generates
    /// a random 16-byte salt. The same input will produce a different output each time.
    /// </summary>
    public class Symmetric_AES_CBC_Passphrase
        : Symmetric_AES_Passphrase
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
