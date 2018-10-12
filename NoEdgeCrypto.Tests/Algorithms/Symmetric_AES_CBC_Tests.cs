using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Core;
using NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Symmetric_AES_CBC_Tests
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
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit)]
        public virtual void TestKey(Symmetric_AES.KeySize keySize)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            Assert.AreEqual((int)keySize, key.Length);
            bool anyNonZero = false;
            foreach (byte b in key)
            {
                anyNonZero |= (b != 0);
            }
            Assert.IsTrue(anyNonZero);
        }

        [TestMethod]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit)]
        public void TestSameInputProducesDifferentOutput(Symmetric_AES.KeySize keySize)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            for (int counter = 0; counter < 10; ++counter)
            {
                var encryptedAsBase64 = new HashSet<string>();
                using (var algorithm = new Symmetric_AES_CBC())
                {
                    var inputBytes = GetRandomBytes(1024, 4096);
                    for (int i = 0; i < 100; ++i)
                    {
                        encryptedAsBase64.Add(Convert.ToBase64String(algorithm.EncryptBytes(inputBytes, key)));
                    }
                }
                Assert.AreEqual(100, encryptedAsBase64.Count, "Should be 100 distinct values");
            }
        }

        [TestMethod]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100000)]
        public void TestRandomBytes(Symmetric_AES.KeySize keySize, int? numBytes)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            byte[] input = null;
            if (numBytes.HasValue)
            {
                input = GetRandomBytes(numBytes.Value, numBytes.Value);
            }
            byte[] encrypted, decrypted;
            using (var algorithm = new Symmetric_AES_CBC())
            {
                encrypted = algorithm.EncryptBytes(input, key);
            }
            using (var algorithm = new Symmetric_AES_CBC())
            {
                decrypted = algorithm.DecryptBytes(encrypted, key);
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
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100000)]
        public void TestRandomString(Symmetric_AES.KeySize keySize, int? numChars)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            string input = null;
            if (numChars.HasValue)
            {
                input = GetRandomString(numChars.Value, numChars.Value);
            }

            byte[] encrypted;
            string decrypted;
            using (var algorithm = new Symmetric_AES_CBC())
            {
                encrypted = algorithm.EncryptString(input, key);
            }
            using (var algorithm = new Symmetric_AES_CBC())
            {
                decrypted = algorithm.DecryptBytes(encrypted, key).AsString();
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
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit)]
        public void TestUnicodeString(Symmetric_AES.KeySize keySize)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100)) + "\u01e2\u01f0\u020e\u0229";
            byte[] encrypted;
            string decrypted;
            using (var algorithm = new Symmetric_AES_CBC())
            {
                encrypted = algorithm.EncryptString(input, key);
            }
            using (var algorithm = new Symmetric_AES_CBC())
            {
                Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");
                decrypted = algorithm.DecryptBytes(encrypted, key).AsString();
            }
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit, 100000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, null)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 0)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 1)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 10000)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit, 100000)]
        public void TestRandomStream(Symmetric_AES.KeySize keySize, int? numBytes)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
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
                    using (var algorithm = new Symmetric_AES_CBC())
                    {
                        algorithm.EncryptStream(inputStream, outputStream, key);
                    }
                    if (numBytes.HasValue)
                    {
                        encrypted = outputStream.ToArray();
                        Assert.IsTrue(encrypted.Length >=numBytes, "encrypted.Length");
                    }
                    else
                    {
                        Assert.IsNull(inputStream, "inputStream");
                        Assert.IsNull(outputStream, "outputStream");
                    }
                }
            }

            using (var inputStream = numBytes.HasValue ? new MemoryStream(encrypted) : null)
            {
                using (var outputStream = numBytes.HasValue ? new MemoryStream() : null)
                {
                    using (var algorithm = new Symmetric_AES_CBC())
                    {
                        algorithm.DecryptStream(inputStream, outputStream, key);
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
        [DataRow(Symmetric_AES.KeySize.KeySize128Bit)]
        [DataRow(Symmetric_AES.KeySize.KeySize256Bit)]
        [ExpectedException(typeof(CryptographicException))]
        public void TestIncorrectKeyFails(Symmetric_AES.KeySize keySize)
        {
            var key = Symmetric_AES.GenerateRandomKey(keySize);
            byte[] input = GetRandomBytes(1000, 5000);
            byte[] encrypted;
            using (var algorithm = new Symmetric_AES_CBC())
            {
                encrypted = algorithm.EncryptBytes(input, key);
            }
            key = Symmetric_AES.GenerateRandomKey(keySize);
            using (var algorithm = new Symmetric_AES_CBC())
            {
                algorithm.DecryptBytes(encrypted, key);
            }
        }
    }
}
