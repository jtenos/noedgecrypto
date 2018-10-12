using System;
using System.IO;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase
{
    /// <summary>
    /// Base class for symmetric encryption using a passphrase.
    /// </summary>
    public abstract class SymmetricAlgorithmBase_Passphrase
        : IDisposable
    {
        /// <summary>
        /// Encrypts a stream using a key derived from the passphrase.
        /// </summary>
        /// <param name="inputStream">The stream to encrypt.</param>
        /// <param name="outputStream">The encrypted stream.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        public abstract void EncryptStream(Stream inputStream, Stream outputStream, string passphrase);

        /// <summary>
        /// Encrypts a string using a key derived from the passphrase.
        /// </summary>
        /// <param name="input">The plaintext input.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        /// <param name="encoding">The string encoding, default is UTF8.</param>
        /// <returns>The encrypted results.</returns>
        public EncryptionResults EncryptString(string input, string passphrase, Encoding encoding = null)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            encoding = encoding ?? Defaults.Encoding;
            return EncryptBytes(encoding.GetBytes(input), passphrase);
        }

        /// <summary>
        /// Encrypts a byte array using a key derived from the passphrase.
        /// </summary>
        /// <param name="input">The plaintext input.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        /// <returns>The encrypted results.</returns>
        public EncryptionResults EncryptBytes(byte[] input, string passphrase)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    EncryptStream(inputStream, outputStream, passphrase);
                    return new EncryptionResults(outputStream.ToArray());
                }
            }
        }

        public void EncryptFileToFile(string inputFile, string outputFile, string passphrase, bool allowOverwrite = false)
        {
            if (!allowOverwrite && File.Exists(outputFile))
            {
                throw new ArgumentException("Output file already exists");
            }

            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
                Thread.Sleep(100);
            }

            using (var inputStream = File.OpenRead(inputFile))
            {
                using (var outputStream = File.OpenWrite(outputFile))
                {
                    EncryptStream(inputStream, outputStream, passphrase);
                }
            }
        }

        public EncryptionResults EncryptSerializableObject(object obj, string passphrase)
        {
            string json = JsonConvert.SerializeObject(obj);
            return EncryptString(json, passphrase);
        }

        /// <summary>
        /// Decrypts a stream using a given key.
        /// </summary>
        /// <param name="inputStream">The encrypted stream.</param>
        /// <param name="outputStream">The decrypted stream.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        public abstract void DecryptStream(Stream inputStream, Stream outputStream, string passphrase);

        /// <summary>
        /// Decrypts a byte array using a given key.
        /// </summary>
        /// <param name="input">The encrypted content.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        /// <returns>The decrypted results.</returns>
        public DecryptionResults DecryptBytes(byte[] input, string passphrase)
        {
            if (input == null)
            {
                return new DecryptionResults(null);
            }
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    DecryptStream(inputStream, outputStream, passphrase);
                    return new DecryptionResults(outputStream.ToArray());
                }
            }
        }

        public DecryptionResults DecryptString(string input, string passphrase, Encoding encoding = null)
        {
            if (encoding == null)
            {
                encoding = Defaults.Encoding;
            }
            byte[] inputBytes = encoding.GetBytes(input);
            return DecryptBytes(inputBytes, passphrase);
        }

        public void DecryptFileToFile(string inputFile, string outputFile, string passphrase, bool allowOverwrite = false)
        {
            if (!allowOverwrite && File.Exists(outputFile))
            {
                throw new ArgumentException("Output file already exists");
            }

            if (File.Exists(outputFile))
            {
                File.Delete(outputFile);
                Thread.Sleep(100);
            }

            using (var inputStream = File.OpenRead(inputFile))
            {
                using (var outputStream = File.OpenWrite(outputFile))
                {
                    DecryptStream(inputStream, outputStream, passphrase);
                }
            }
        }

        public T DecryptSerializableObject<T>(byte[] input, string passphrase)
        {
            byte[] decryptedBytes = DecryptBytes(input, passphrase);
            string decryptedJSON = Defaults.Encoding.GetString(decryptedBytes);
            return JsonConvert.DeserializeObject<T>(decryptedJSON);
        }


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

        ~SymmetricAlgorithmBase_Passphrase()
        {
            Dispose(false);
        }
        #endregion
    }
}
