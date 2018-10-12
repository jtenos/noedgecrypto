using System;
using System.IO;
using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms
{
    /// <summary>
    /// Symmetric encryption using AesCryptoServiceProvider.
    /// </summary>
    public abstract class Symmetric_AES
        : SymmetricAlgorithmBase
    {
        /// <summary>
        /// Valid key sizes for AES: 16 or 32 bytes.
        /// </summary>
        public enum KeySize
        {
            KeySize128Bit = 128 / 8,
            KeySize256Bit = 256 / 8
        }

        private void ValidateKey(byte[] key)
        {
            if (key == null)
            {
                throw new ArgumentNullException("key");
            }

            int? keySizeBytes = null;
            foreach (KeySize keySize in Enum.GetValues(typeof(KeySize)))
            {
                if ((int)keySize == key.Length)
                {
                    keySizeBytes = (int)keySize;
                    break;
                }
            }
            if (!keySizeBytes.HasValue)
            {
                throw new ArgumentException("The key must be 16 or 32 bytes");
            }
        }

        /// <summary>
        /// Generates a random key.
        /// </summary>
        /// <param name="keySize">The key size to use. Default is 32.</param>
        /// <returns>A random byte array which can be used as a key for AES encryption.</returns>
        public static byte[] GenerateRandomKey(KeySize keySize = KeySize.KeySize256Bit)
        {
            return SecureRandomizer.GetRandomBytes((int)keySize);
        }

        protected abstract CipherMode GetCipherMode();

        protected abstract int GetIVSizeBytes();

        /// <summary>
        /// Encrypts a stream using a given key.
        /// </summary>
        /// <param name="inputStream">The stream to encrypt.</param>
        /// <param name="outputStream">The encrypted stream.</param>
        /// <param name="key">The key to use for encryption.</param>
        public override void EncryptStream(Stream inputStream, Stream outputStream, byte[] key)
        {
            ValidateKey(key);
            if (inputStream == null || outputStream == null)
            {
                throw new ArgumentNullException();
            }

            byte[] iv = null;
            int ivLength = GetIVSizeBytes();
            if (ivLength != 0)
            {
                iv = SecureRandomizer.GetRandomBytes(ivLength);
                outputStream.Write(iv, 0, iv.Length);
            }

            using (var algo = new AesCryptoServiceProvider())
            {
                algo.Mode = GetCipherMode();
                using (var encryptor = algo.CreateEncryptor(key, iv))
                {
                    using (var cryptoStream = new CryptoStream(outputStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var binaryWriter = new BinaryWriter(cryptoStream))
                        {
                            var buffer = new byte[Defaults.BUFFER_SIZE];
                            int count;
                            while ((count = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                binaryWriter.Write(buffer, 0, count);
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Decrypts a stream using a given key.
        /// </summary>
        /// <param name="inputStream">The encrypted stream.</param>
        /// <param name="outputStream">The decrypted stream.</param>
        /// <param name="key">The key to use for decryption.</param>
        public override void DecryptStream(Stream inputStream, Stream outputStream, byte[] key)
        {
            ValidateKey(key);
            if (inputStream == null)
            {
                return;
            }

            byte[] iv = null;
            int ivLength = GetIVSizeBytes();
            if (ivLength != 0)
            {
                iv = new byte[ivLength];
                inputStream.Read(iv, 0, iv.Length);
            }

            using (var algo = new AesCryptoServiceProvider())
            {
                algo.Mode = GetCipherMode();
                using (var decryptor = algo.CreateDecryptor(key, iv))
                {
                    using (var decryptorStream = new CryptoStream(outputStream, decryptor, CryptoStreamMode.Write))
                    {
                        using (var binaryWriter = new BinaryWriter(decryptorStream))
                        {
                            var buffer = new byte[Defaults.BUFFER_SIZE];
                            int count;
                            while ((count = inputStream.Read(buffer, 0, buffer.Length)) > 0)
                            {
                                binaryWriter.Write(buffer, 0, count);
                            }
                        }
                    }
                }
            }
        }
    }
}
