using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase
{
    /// <summary>
    /// Symmetric encryption using AES with ECB. A 256-bit key is generated using PBKDF2 with 16384 iterations, and generates
    /// a random 16-byte salt. The same input will generate a different output each time because of the different salt, but
    /// the encryption algorithm is still using ECB, and should not be used unless you have a reason to.
    /// </summary>
    public class Symmetric_AES_ECB_Passphrase
        : Symmetric_AES_Passphrase
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
