using System;
using System.Security.Cryptography;

namespace NoEdgeCrypto.Core.Algorithms.AsymmetricAlgorithms
{
    /// <summary>
    /// Asymmetric encryption using .NET's RSACryptoServiceProvider.
    /// </summary>
    public class Asymmetric_RSA
        : AsymmetricAlgorithmBase
    {
        protected override byte[] EncryptBytesImpl(byte[] input, string publicKeyXml)
        {
            if (input == null)
            {
                return null;
            }
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXml);
                int maxLengthPlusOne = ((rsa.KeySize - 384) / 8) + 7;
                if (input.Length >= maxLengthPlusOne)
                {
                    throw new ArgumentException(string.Format("Invalid message size. must be less than {0} bytes: ((KeySize - 384) / 8) + 7", maxLengthPlusOne));
                }
                return rsa.Encrypt(input, true);
            }
        }

        protected override byte[] DecryptBytesImpl(byte[] input, string privateKeyXml)
        {
            if (input == null)
            {
                return null;
            }
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                return rsa.Decrypt(input, true);
            }
        }

        /// <summary>
        /// Generates a random RSA key using a new instance of RSACryptoServiceProvider.
        /// </summary>
        /// <param name="privateKeyXml">The private key XML representation.</param>
        /// <param name="publicKeyXml">The public key XML representation.</param>
        /// <param name="keySizeInBits">The key size in bits. Default is 2048.</param>
        public static void GenerateRandomPrivateKey(out string privateKeyXml, out string publicKeyXml, int keySizeInBits = 2048)
        {
            using (var rsa = new RSACryptoServiceProvider(keySizeInBits))
            {
                bool keySizeValid = false;
                foreach (var lks in rsa.LegalKeySizes)
                {
                    if (keySizeInBits >= lks.MinSize && keySizeInBits <= lks.MaxSize && (lks.MaxSize - keySizeInBits) % lks.SkipSize == 0)
                    {
                        keySizeValid = true;
                    }
                }
                if (!keySizeValid)
                {
                    throw new ArgumentException("Invalid key size");
                }

                privateKeyXml = rsa.ToXmlString(true);
                publicKeyXml = rsa.ToXmlString(false);
            }
        }

        /// <summary>
        /// Pulls the public key from a private key, by importing the private key XML and exporting the public key XML.
        /// </summary>
        /// <param name="privateKeyXml">The private key XML.</param>
        /// <returns>The public key XML.</returns>
        public static string GetPublicKeyFromPrivateKey(string privateKeyXml)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                return rsa.ToXmlString(false);
            }
        }
    }
}
