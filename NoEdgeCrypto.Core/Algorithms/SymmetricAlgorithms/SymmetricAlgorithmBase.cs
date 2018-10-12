using System;
using System.IO;
using System.Text;
using System.Threading;
using Newtonsoft.Json;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms
{
    /// <summary>
    /// Base class for symmetric encryption. Classes deriving from this class will use a byte array
    /// as its encryption/decryption key.
    /// </summary>
    public abstract class SymmetricAlgorithmBase
        : IDisposable
    {
        /// <summary>
        /// Encrypts a stream using a given key.
        /// </summary>
        /// <param name="inputStream">The stream to encrypt.</param>
        /// <param name="outputStream">The encrypted stream.</param>
        /// <param name="key">The key to use for encryption.</param>
        public abstract void EncryptStream(Stream inputStream, Stream outputStream, byte[] key);

        /// <summary>
        /// Encrypts a string using a given key.
        /// </summary>
        /// <param name="input">The text to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <param name="encoding">The string encoding. Default is UTF8.</param>
        /// <returns>The encrypted results.</returns>
        public EncryptionResults EncryptString(string input, byte[] key, Encoding encoding = null)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            encoding = encoding ?? Defaults.Encoding;
            return EncryptBytes(encoding.GetBytes(input), key);
        }

        /// <summary>
        /// Encrypts a byte array using a given key.
        /// </summary>
        /// <param name="input">The byte array to encrypt.</param>
        /// <param name="key">The key to use for encryption.</param>
        /// <returns>The encrypted results.</returns>
        public EncryptionResults EncryptBytes(byte[] input, byte[] key)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    EncryptStream(inputStream, outputStream, key);
                    return new EncryptionResults(outputStream.ToArray());
                }
            }
        }

        public EncryptionResults EncryptFile(string inputFile, byte[] key)
        {
            using (var inputStream = File.OpenRead(inputFile))
            {
                using (var outputStream = new MemoryStream())
                {
                    EncryptStream(inputStream, outputStream, key);
                    return new EncryptionResults(outputStream.ToArray());
                }
            }
        }

        public void EncryptFileToFile(string inputFile, string outputFile, byte[] key, bool allowOverwrite = false)
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
                    EncryptStream(inputStream, outputStream, key);
                }
            }
        }

        public EncryptionResults EncryptSerializableObject(object obj, byte[] key)
        {
            string json = JsonConvert.SerializeObject(obj);
            return EncryptString(json, key);
        }

        /// <summary>
        /// Decrypts a stream using a given key.
        /// </summary>
        /// <param name="inputStream">The encrypted stream.</param>
        /// <param name="outputStream">The decrypted stream.</param>
        /// <param name="key">The key to use for decryption.</param>
        public abstract void DecryptStream(Stream inputStream, Stream outputStream, byte[] key);

        /// <summary>
        /// Decrypts a byte array using a given key.
        /// </summary>
        /// <param name="input">The byte array to decrypt.</param>
        /// <param name="key">The key to use for decryption.</param>
        /// <returns></returns>
        public DecryptionResults DecryptBytes(byte[] input, byte[] key)
        {
            if (input == null)
            {
                return new DecryptionResults(null);
            }
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    DecryptStream(inputStream, outputStream, key);
                    return new DecryptionResults(outputStream.ToArray());
                }
            }
        }

        public DecryptionResults DecryptBase64(string input, byte[] key)
        {
            byte[] inputBytes = Convert.FromBase64String(input);
            return DecryptBytes(inputBytes, key);
        }

        public void DecryptFileToFile(string inputFile, string outputFile, byte[] key, bool allowOverwrite = false)
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
                    DecryptStream(inputStream, outputStream, key);
                }
            }
        }

        public T DecryptSerializableObject<T>(byte[] input, byte[] key)
        {
            byte[] decryptedBytes = DecryptBytes(input, key);
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

        ~SymmetricAlgorithmBase()
        {
            Dispose(false);
        }
        #endregion
    }
}
