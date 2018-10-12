using System.IO;
using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase
{
    /// <summary>
    /// Symmetric encryption using AesCryptoServiceProvider.
    /// </summary>
    public abstract class Symmetric_AES_Passphrase
        : SymmetricAlgorithmBase_Passphrase
    {
        private const int SALT_SIZE_BYTES = 16;
        private const int KEY_SIZE_BYTES = 32;

        protected abstract CipherMode GetCipherMode();

        protected abstract int GetIVSizeBytes();

        /// <summary>
        /// Encrypts a stream using a key derived from the passphrase.
        /// </summary>
        /// <param name="inputStream">The stream to encrypt.</param>
        /// <param name="outputStream">The encrypted stream.</param>
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        public override void EncryptStream(Stream inputStream, Stream outputStream, string passphrase)
        {
            if (inputStream == null || outputStream == null)
            {
                return;
            }

            byte[] salt;
            byte[] key = PBKDF2.ComputeHash(passphrase, out salt, saltNumBytes: SALT_SIZE_BYTES, passwordNumBytes: KEY_SIZE_BYTES);

            byte[] iv = null;
            int ivLength = GetIVSizeBytes();
            if (ivLength != 0)
            {
                iv = SecureRandomizer.GetRandomBytes(ivLength);
                outputStream.Write(iv, 0, iv.Length);
            }

            outputStream.Write(salt, 0, salt.Length);

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
        /// <param name="passphrase">The passphrase from which the encryption key is derived.</param>
        public override void DecryptStream(Stream inputStream, Stream outputStream, string passphrase)
        {
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

            byte[] salt = new byte[SALT_SIZE_BYTES];
            inputStream.Read(salt, 0, salt.Length);

            byte[] key = PBKDF2.ComputeHash(passphrase, salt, passwordNumBytes: KEY_SIZE_BYTES);

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
