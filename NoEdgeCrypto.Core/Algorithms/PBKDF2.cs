using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms
{
    /// <summary>
    /// Wrapper around Rfc2898DeriveBytes for computing PBKDF2.
    /// </summary>
    public static class PBKDF2
    {
        private const int DEFAULT_NUM_ITERATIONS = 0x4000;
        private const int DEFAULT_PASSWORD_NUM_BYTES = 32;
        private const int DEFAULT_SALT_NUM_BYTES = 32;

        /// <summary>
        /// Computes a hash with a given plaintext password and salt.
        /// </summary>
        /// <param name="plaintextPassword">The plaintext password.</param>
        /// <param name="salt">The known salt.</param>
        /// <param name="numIterations">Number of iterations. Default is 16384.</param>
        /// <param name="passwordNumBytes">The number of bytes to generate for the output. Default is 32.</param>
        /// <returns>The hash output.</returns>
        public static byte[] ComputeHash(string plaintextPassword, byte[] salt, int numIterations = DEFAULT_NUM_ITERATIONS,
            int passwordNumBytes = DEFAULT_PASSWORD_NUM_BYTES)
        {
            using (var rfc = new Rfc2898DeriveBytes(plaintextPassword, salt, numIterations))
            {
                return rfc.GetBytes(passwordNumBytes);
            }
        }

        /// <summary>
        /// Computes a hash and creates a random salt.
        /// </summary>
        /// <param name="plaintextPassword">The plaintext password.</param>
        /// <param name="salt">The salt which will be created.</param>
        /// <param name="numIterations">Number of iterations. Default is 16384.</param>
        /// <param name="passwordNumBytes">The number of bytes to generate for the output. Default is 32.</param>
        /// <param name="saltNumBytes">The number of bytes to generate for the salt. Default is 32.</param>
        /// <returns></returns>
        public static byte[] ComputeHash(string plaintextPassword, out byte[] salt, int numIterations = DEFAULT_NUM_ITERATIONS,
            int passwordNumBytes = DEFAULT_PASSWORD_NUM_BYTES, int saltNumBytes = DEFAULT_SALT_NUM_BYTES)
        {
            using (var rfc = new Rfc2898DeriveBytes(plaintextPassword, saltNumBytes, numIterations))
            {
                salt = rfc.Salt;
                return rfc.GetBytes(passwordNumBytes);
            }
        }
    }
}
