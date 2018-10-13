// Apparently RSA doesn't work on .NET Standard

//using System;
//using System.Text;
//using NoEdgeCrypto.Core.Results;

//namespace NoEdgeCrypto.Core.Algorithms.AsymmetricAlgorithms
//{
//    /// <summary>
//    /// Base class for asymmetric encryption.
//    /// </summary>
//    public abstract class AsymmetricAlgorithmBase
//        : IDisposable
//    {
//        /// <summary>
//        /// Encrypts a string using a public key and a given encoding.
//        /// </summary>
//        /// <param name="input">The string to encrypt.</param>
//        /// <param name="publicKeyXml">The public key XML representation.</param>
//        /// <param name="encoding">The encoding on the string - default is UTF8.</param>
//        /// <returns>The encrypted results.</returns>
//        public EncryptionResults EncryptString(string input, string publicKeyXml, Encoding encoding = null)
//        {
//            if (input == null)
//            {
//                return new EncryptionResults(null);
//            }
//            encoding = encoding ?? Defaults.Encoding;
//            return EncryptBytes(encoding.GetBytes(input), publicKeyXml);
//        }

//        /// <summary>
//        /// Encrypts a byte array using a public key and a given encoding.
//        /// </summary>
//        /// <param name="input">The byte array to encrypt.</param>
//        /// <param name="publicKeyXml">The public key XML representation.</param>
//        /// <returns>The encrypted results.</returns>
//        public EncryptionResults EncryptBytes(byte[] input, string publicKeyXml)
//        {
//            if (input == null)
//            {
//                return new EncryptionResults(null);
//            }
//            return new EncryptionResults(EncryptBytesImpl(input, publicKeyXml));
//        }

//        protected abstract byte[] EncryptBytesImpl(byte[] input, string publicKeyXml);

//        /// <summary>
//        /// Decrypts an asymmetric-encrypted byte array, using a given private key.
//        /// </summary>
//        /// <param name="input">The ciphertext to decrypt.</param>
//        /// <param name="privateKeyXml">The private key XML representation.</param>
//        /// <returns>The decrypted output as a DecryptionResults object, which can then
//        /// be converted back to its original type.</returns>
//        public DecryptionResults DecryptBytes(byte[] input, string privateKeyXml)
//        {
//            if (input == null)
//            {
//                return new DecryptionResults(null);
//            }
//            return new DecryptionResults(DecryptBytesImpl(input, privateKeyXml));
//        }

//        public DecryptionResults DecryptBase64(string input, string privateKeyXml)
//        {
//            if (input == null)
//            {
//                return new DecryptionResults(null);
//            }
//            return DecryptBytes(Convert.FromBase64String(input), privateKeyXml);
//        }

//        protected abstract byte[] DecryptBytesImpl(byte[] input, string privateKeyXml);

//        #region Disposable
//        private bool _disposed;

//        void IDisposable.Dispose()
//        {
//            Dispose(true);
//            GC.SuppressFinalize(this);
//        }

//        protected void Dispose(bool disposing)
//        {
//            if (!_disposed)
//            {
//                if (disposing)
//                {
//                    DisposeManagedResources();
//                }

//                DisposeUnmanagedResources();
//                _disposed = true;
//            }
//        }

//        protected virtual void DisposeManagedResources()
//        {
//        }

//        protected virtual void DisposeUnmanagedResources()
//        {
//        }

//        ~AsymmetricAlgorithmBase()
//        {
//            Dispose(false);
//        }
//        #endregion
//    }
//}
