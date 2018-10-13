using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Core;
using NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Symmetric_AES_ECB_Passphrase_Tests
        : BaseTest
    {
        [TestInitialize]
        public virtual void SetUp()
        {
        }

        [TestCleanup]
        public virtual void TearDown()
        {
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(100)]
        [DataRow(10000)]
        [DataRow(100000)]
        public void TestRandomBytes(int? numBytes)
        {
            string passphrase = Guid.NewGuid().ToString("N");
            byte[] input = null;
            if (numBytes.HasValue)
            {
                input = GetRandomBytes(numBytes.Value, numBytes.Value);
            }
            byte[] encrypted, decrypted;
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                encrypted = algorithm.EncryptBytes(input, passphrase);
            }
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                decrypted = algorithm.DecryptBytes(encrypted, passphrase);
            }
            if (input == null)
            {
                Assert.IsNull(encrypted, "encrypted");
                Assert.IsNull(decrypted, "decrypted");
            }
            else
            {
                Assert.IsTrue(encrypted.Length >= numBytes, "encrypted.Length");
                Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
            }
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(100)]
        [DataRow(10000)]
        [DataRow(100000)]
        public void TestRandomString(int? numChars)
        {
            string passphrase = Guid.NewGuid().ToString("N");
            string input = null;
            if (numChars.HasValue)
            {
                input = GetRandomString(numChars.Value, numChars.Value);
            }

            byte[] encrypted;
            string decrypted;
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                encrypted = algorithm.EncryptString(input, passphrase);
            }
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                decrypted = algorithm.DecryptBytes(encrypted, passphrase).AsString();
            }
            if (input == null)
            {
                Assert.IsNull(encrypted, "encrypted");
                Assert.IsNull(decrypted, "decrypted");
            }
            else
            {
                Assert.IsTrue(encrypted.Length >= input.Length, "encrypted.Length");
                Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
            }
        }

        [TestMethod]
        public void TestUnicodeString()
        {
            string passphrase = Guid.NewGuid().ToString("N");
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100)) + "\u01e2\u01f0\u020e\u0229";
            byte[] encrypted;
            string decrypted;
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                encrypted = algorithm.EncryptString(input, passphrase);
            }
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");
                decrypted = algorithm.DecryptBytes(encrypted, passphrase).AsString();
            }
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(0)]
        [DataRow(1)]
        [DataRow(100)]
        [DataRow(10000)]
        [DataRow(100000)]
        public void TestRandomStream(int? numBytes)
        {
            string passphrase = Guid.NewGuid().ToString("N");
            byte[] input = null;
            if (numBytes.HasValue)
            {
                input = GetRandomBytes(numBytes.Value, numBytes.Value);
            }
            byte[] encrypted = null;

            using (var inputStream = numBytes.HasValue ? new MemoryStream(input) : null)
            {
                using (var outputStream = numBytes.HasValue ? new MemoryStream() : null)
                {
                    using (var algorithm = new Symmetric_AES_ECB_Passphrase())
                    {
                        try
                        {
                            algorithm.EncryptStream(inputStream, outputStream, passphrase);
                            if (numBytes.HasValue)
                            {
                                encrypted = outputStream.ToArray();
                                Assert.IsTrue(encrypted.Length >= numBytes, "encrypted.Length");
                            }
                            else
                            {
                                Assert.Fail("Should have thrown exception");
                            }
                        }
                        catch (Exception ex)
                        {
                            if (numBytes.HasValue)
                            {
                                Assert.Fail("Should not have thrown exception");
                            }
                            else
                            {
                                Assert.IsNull(inputStream, "inputStream");
                                Assert.IsNull(outputStream, "outputStream");
                            }

                        }
                    }
                }
            }

            using (var inputStream = numBytes.HasValue ? new MemoryStream(encrypted) : null)
            {
                using (var outputStream = numBytes.HasValue ? new MemoryStream() : null)
                {
                    using (var algorithm = new Symmetric_AES_ECB_Passphrase())
                    {
                        algorithm.DecryptStream(inputStream, outputStream, passphrase);
                    }
                    if (numBytes.HasValue)
                    {
                        byte[] decrypted = outputStream.ToArray();
                        Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
                    }
                    else
                    {
                        Assert.IsNull(inputStream, "inputStream");
                        Assert.IsNull(outputStream, "outputStream");
                    }
                }
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestIncorrectKeyFails()
        {
            string passphrase = Guid.NewGuid().ToString("N");
            byte[] input = GetRandomBytes(1000, 5000);
            byte[] encrypted;
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                encrypted = algorithm.EncryptBytes(input, passphrase);
            }
            passphrase = Guid.NewGuid().ToString("N");
            using (var algorithm = new Symmetric_AES_ECB_Passphrase())
            {
                algorithm.DecryptBytes(encrypted, passphrase);
            }
        }
    }
}
