using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using NoEdgeCrypto.Core.Results;

namespace NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Authenticated
{
    /// <summary>
    /// Symmetric-authenticated encryption using AES CBC with a 256-bit AES crypto key, with HMACSHA256.
    /// You will need both a 32-byte crypto key and a 32-byte auth key.
    /// </summary>
    public class SymmetricAuthenticated_AES_HMACSHA256
        : SymmetricAuthenticatedAlgorithmBase
    {
        private const int KEY_SIZE_BYTES = 32;
        private const int IV_SIZE_BYTES = 16;

        /// <summary>
        /// Encrypts a message using 256-bit AES CBC encryption with HMACSHA256.
        /// </summary>
        /// <param name="input">The plaintext input.</param>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        /// <returns>The encrypted message. The first 16 bytes are the IV, followed by
        /// the ciphertext, then the last 32 bytes are the HMAC tag.</returns>
        public override EncryptionResults EncryptBytes(byte[] input, byte[] cryptoKey, byte[] authKey)
        {
            if (input == null)
            {
                return new EncryptionResults(null);
            }
            ValidateKeys(cryptoKey, authKey);

            byte[] iv = SecureRandomizer.GetRandomBytes(IV_SIZE_BYTES);

            byte[] cipherText;
            using (var algo = new AesCryptoServiceProvider())
            {
                algo.Mode = CipherMode.CBC;
                using (var encryptor = algo.CreateEncryptor(cryptoKey, iv))
                {
                    using (var inputStream = new MemoryStream(input))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
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
                            cipherText = memoryStream.ToArray();
                        }
                    }
                }
            }

            using (var hashAlgo = new HMACSHA256(authKey))
            {
                using (var memoryStream = new MemoryStream())
                {
                    using (var binaryWriter = new BinaryWriter(memoryStream))
                    {
                        binaryWriter.Write(iv);
                        binaryWriter.Write(cipherText);
                        binaryWriter.Flush();
                        var tag = hashAlgo.ComputeHash(memoryStream.ToArray());
                        binaryWriter.Write(tag);
                    }
                    return new EncryptionResults(memoryStream.ToArray());
                }
            }
        }

        /// <summary>
        /// Decrypts a message using 256-bit AES CBC encryption with HMACSHA256. This will validate
        /// the HMAC tag, which is the last 32 bytes of the message, as a HMAC tag computed against
        /// (iv+ciphertext). If that passes, the message is decrypted using the given key.
        /// </summary>
        /// <param name="input">The encrypted contents.</param>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        /// <returns>The decrypted output.</returns>
        public override DecryptionResults DecryptBytes(byte[] input, byte[] cryptoKey, byte[] authKey)
        {
            if (input == null)
            {
                return new DecryptionResults(null);
            }
            ValidateKeys(cryptoKey, authKey);


            using (var hashAlgo = new HMACSHA256(authKey))
            {
                // The last 32 bytes of the file.
                var sentTag = new byte[hashAlgo.HashSize / 8];
                Array.Copy(input, input.Length - sentTag.Length, sentTag, 0, sentTag.Length);

                // The calculated tag based on all but the last 32 bytes of the file.
                byte[] calcTag = hashAlgo.ComputeHash(input, 0, input.Length - sentTag.Length);

                if (!sentTag.SequenceEqual(calcTag))
                {
                    throw new CryptographicException("Authorization failed.");
                }

                byte[] iv = new byte[IV_SIZE_BYTES];
                Array.Copy(input, 0, iv, 0, iv.Length);

                // Pull the IV and the sent tag out of the input, leaving only the ciphertext.
                byte[] tmp = new byte[input.Length - iv.Length - sentTag.Length];
                Array.Copy(input, iv.Length, tmp, 0, tmp.Length);
                input = tmp;

                using (var algo = new AesCryptoServiceProvider())
                {
                    algo.Mode = CipherMode.CBC;
                    using (var inputStream = new MemoryStream(input))
                    {
                        using (var decryptor = algo.CreateDecryptor(cryptoKey, iv))
                        {
                            using (var outputStream = new MemoryStream())
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
                                return new DecryptionResults(outputStream.ToArray());
                            }
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Generates two random 32-byte arrays, for use with this class's encryption methods.
        /// </summary>
        /// <param name="cryptoKey">The 32-byte crypto key.</param>
        /// <param name="authKey">The 32-byte auth key.</param>
        public static void GenerateKeys(out byte[] cryptoKey, out byte[] authKey)
        {
            cryptoKey = SecureRandomizer.GetRandomBytes(KEY_SIZE_BYTES);
            authKey = SecureRandomizer.GetRandomBytes(KEY_SIZE_BYTES);
        }

        private void ValidateKeys(byte[] cryptoKey, byte[] authKey)
        {
            if (cryptoKey == null || cryptoKey.Length != KEY_SIZE_BYTES)
            {
                throw new ArgumentException("Invalid crypto key - must be 32 bytes");
            }

            if (authKey == null || authKey.Length != KEY_SIZE_BYTES)
            {
                throw new ArgumentException("Invalid auth key");
            }
        }
    }
}
