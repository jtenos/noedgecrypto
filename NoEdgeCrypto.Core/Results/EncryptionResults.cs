namespace NoEdgeCrypto.Core.Results
{
    /// <summary>
    /// Wrapper around a byte array, used for encryption results.
    /// </summary>
    public class EncryptionResults
        : BinaryResults
    {
        /// <summary>
        /// Creates the wrapper around a byte array.
        /// </summary>
        /// <param name="encryptedBytes">The bytes that this object represents.</param>
        public EncryptionResults(byte[] encryptedBytes)
            : base(encryptedBytes)
        {
        }

        public static implicit operator byte[](EncryptionResults encryptionResults)
        {
            return encryptionResults.AsBytes();
        }
    }
}
