namespace NoEdgeCrypto.Core.Results
{
    public class HashResults
        : BinaryResults
    {
        /// <summary>
        /// Creates the wrapper around a byte array.
        /// </summary>
        /// <param name="hashedBytes">The bytes that this object represents.</param>
        public HashResults(byte[] hashedBytes)
            : base(hashedBytes)
        {
        }

        public static implicit operator byte[](HashResults hashResults)
        {
            return hashResults.AsBytes();
        }
    }
}
