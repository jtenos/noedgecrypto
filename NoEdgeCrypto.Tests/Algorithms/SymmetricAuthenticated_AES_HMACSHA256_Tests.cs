using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using NoEdgeCrypto.Core;
using NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Authenticated;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class SymmetricAuthenticated_AES_HMACSHA256_Tests
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
        public virtual void TestKeys()
        {
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            Assert.AreEqual(32, cryptoKey.Length);
            Assert.AreEqual(32, authKey.Length);

            bool anyNonZero = false;
            foreach (byte b in cryptoKey)
            {
                anyNonZero |= (b != 0);
            }
            Assert.IsTrue(anyNonZero);

            anyNonZero = false;
            foreach (byte b in authKey)
            {
                anyNonZero |= (b != 0);
            }
            Assert.IsTrue(anyNonZero);
        }

        [TestMethod]
        public void TestSameInputProducesDifferentOutput()
        {
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            for (int counter = 0; counter < 10; ++counter)
            {
                var encryptedAsBase64 = new HashSet<string>();
                using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
                {
                    var inputBytes = GetRandomBytes(1024, 4096);
                    for (int i = 0; i < 100; ++i)
                    {
                        encryptedAsBase64.Add(Convert.ToBase64String(algorithm.EncryptBytes(inputBytes, cryptoKey, authKey)));
                    }
                }
                Assert.AreEqual(100, encryptedAsBase64.Count, "Should be 100 distinct values");
            }
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
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            byte[] input = null;
            if (numBytes.HasValue)
            {
                input = GetRandomBytes(numBytes.Value, numBytes.Value);
            }
            byte[] encrypted, decrypted;
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                encrypted = algorithm.EncryptBytes(input, cryptoKey, authKey);
            }
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                decrypted = algorithm.DecryptBytes(encrypted, cryptoKey, authKey);
            }
            if (input == null)
            {
                Assert.IsNull(encrypted, "encrypted");
                Assert.IsNull(decrypted, "decrypted");
            }
            else
            {
                Assert.IsTrue(encrypted.Length >=numBytes, "encrypted.Length");
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
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            string input = null;
            if (numChars.HasValue)
            {
                input = GetRandomString(numChars.Value, numChars.Value);
            }

            byte[] encrypted;
            string decrypted;
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                encrypted = algorithm.EncryptString(input, cryptoKey, authKey);
            }
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                decrypted = algorithm.DecryptBytes(encrypted, cryptoKey, authKey).AsString();
            }
            if (input == null)
            {
                Assert.IsNull(encrypted, "encrypted");
                Assert.IsNull(decrypted, "decrypted");
            }
            else
            {
                Assert.IsTrue(encrypted.Length >=input.Length, "encrypted.Length");
                Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
            }
        }

        [TestMethod]
        public void TestUnicodeString()
        {
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100)) + "\u01e2\u01f0\u020e\u0229";
            byte[] encrypted;
            string decrypted;
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                encrypted = algorithm.EncryptString(input, cryptoKey, authKey);
            }
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");
                decrypted = algorithm.DecryptBytes(encrypted, cryptoKey, authKey).AsString();
            }
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestIncorrectKeyFails()
        {
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            byte[] input = GetRandomBytes(1000, 5000);
            byte[] encrypted;
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                encrypted = algorithm.EncryptBytes(input, cryptoKey, authKey);
            }
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                algorithm.DecryptBytes(encrypted, cryptoKey, authKey);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(CryptographicException))]
        public void TestInvalidAuthentication()
        {
            byte[] cryptoKey, authKey;
            SymmetricAuthenticated_AES_HMACSHA256.GenerateKeys(out cryptoKey, out authKey);
            byte[] input = GetRandomBytes(500, 1000);
            byte[] encrypted, decrypted;
            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                encrypted = algorithm.EncryptBytes(input, cryptoKey, authKey);
            }

            // Change the last byte in the file, which is the 
            encrypted[encrypted.GetUpperBound(0)] = (byte)(~encrypted[encrypted.GetUpperBound(0)]);

            using (var algorithm = new SymmetricAuthenticated_AES_HMACSHA256())
            {
                decrypted = algorithm.DecryptBytes(encrypted, cryptoKey, authKey);
            }

            Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
        }
    }
}
