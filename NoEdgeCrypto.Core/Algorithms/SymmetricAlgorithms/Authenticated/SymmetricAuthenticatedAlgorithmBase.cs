using System;
using System.Text;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Authenticated
{
    public abstract class SymmetricAuthenticatedAlgorithmBase
        : IDisposable
    {
        /// <summary>
        /// Encrypts a string using 256-bit AES CBC encryption with HMACSHA256.
        /// </summary>
        /// <param name="input">The plaintext input.</param>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        /// <param name="encoding">The string encoding. Default is UTF8.</param>
        /// <returns>The encrypted message. The first 16 bytes are the IV, followed by
        /// the ciphertext, then the last 32 bytes are the HMAC tag.</returns>
        public EncryptionResults EncryptString(string input, byte[] cryptoKey, byte[] authKey, Encoding encoding = null)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            encoding = encoding ?? Defaults.Encoding;
            return EncryptBytes(encoding.GetBytes(input), cryptoKey, authKey);
        }

        /// <summary>
        /// Encrypts a message using 256-bit AES CBC encryption with HMACSHA256.
        /// </summary>
        /// <param name="input">The plaintext input.</param>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        /// <returns>The encrypted message. The first 16 bytes are the IV, followed by
        /// the ciphertext, then the last 32 bytes are the HMAC tag.</returns>
        public abstract EncryptionResults EncryptBytes(byte[] input, byte[] cryptoKey, byte[] authKey);

        /// <summary>
        /// Decrypts a message using 256-bit AES CBC encryption with HMACSHA256. This will validate
        /// the HMAC tag, which is the last 32 bytes of the message, as a HMAC tag computed against
        /// (iv+ciphertext). If that passes, the message is decrypted using the given key.
        /// </summary>
        /// <param name="input">The encrypted contents.</param>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        /// <returns>The decrypted output.</returns>
        public abstract DecryptionResults DecryptBytes(byte[] input, byte[] cryptoKey, byte[] authKey);

        #region Disposable
        private bool _disposed;

        void IDisposable.Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    DisposeManagedResources();
                }

                DisposeUnmanagedResources();
                _disposed = true;
            }
        }

        protected virtual void DisposeManagedResources()
        {
        }

        protected virtual void DisposeUnmanagedResources()
        {
        }

        ~SymmetricAuthenticatedAlgorithmBase()
        {
            Dispose(false);
        }
        #endregion    
    }
}
