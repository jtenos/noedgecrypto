// Apparently RSA doesn't work on .NET Standard

//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Security.Cryptography;
//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using NoEdgeCrypto.Core.Algorithms.AsymmetricAlgorithms;

//namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
//{
//    [TestClass]
//    public class Asymmetric_RSA_Tests
//        : BaseTest
//    {
//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        public void TestDistinctKeys(int keySizeInBits)
//        {
//            var privateKeys = new HashSet<string>();
//            var publicKeys = new HashSet<string>();
//            for (int i = 0; i < 4; ++i)
//            {
//                string privateXml, publicXml;
//                Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//                privateKeys.Add(privateXml);
//                publicKeys.Add(publicXml);
//            }
//            Assert.AreEqual(4, privateKeys.Count, "Number of distinct private keys");
//            Assert.AreEqual(4, publicKeys.Count, "Number of distinct public keys");
//        }

//        [TestMethod]
//        [DataRow(0)]
//        [DataRow(376)]
//        [DataRow(1001)]
//        [DataRow(16383)]
//        [DataRow(16392)]
//        [ExpectedException(typeof(ArgumentException))]
//        public void TestInvalidKeySize(int keySizeInBits)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        [ExpectedException(typeof(CryptographicException))]
//        public void TestCannotDecryptWithPublicKey(int keySizeInBits)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            byte[] input = GetRandomBytes(6, 6);
//            byte[] encrypted;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptBytes(input, publicXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                algorithm.DecryptBytes(encrypted, publicXml);
//            }
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        public void TestCanEncryptWithEitherPrivateOrPublicKey(int keySizeInBits)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            byte[] input = GetRandomBytes(6, 6);
//            byte[] encrypted, encrypted2, decrypted, decrypted2;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptBytes(input, publicXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                decrypted = algorithm.DecryptBytes(encrypted, privateXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted2 = algorithm.EncryptBytes(input, privateXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                decrypted2 = algorithm.DecryptBytes(encrypted2, privateXml);
//            }

//            Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
//            Assert.IsTrue(decrypted2.SequenceEqual(input), "Decrypted2 does not match original.");
//        }

//        [TestMethod]
//        [DataRow(384, 7)]
//        [DataRow(1024, 87)]
//        [DataRow(2048, 215)]
//        [DataRow(4096, 471)]
//        [ExpectedException(typeof(ArgumentException))]
//        public void TestEncryptTooLarge(int keySizeInBits, int messageSizeInBytes)
//        {
//            string privateKeyXml, publicKeyXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateKeyXml, out publicKeyXml, keySizeInBits);
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                algorithm.EncryptBytes(new byte[messageSizeInBytes], publicKeyXml);
//            }
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        public void TestEncryptProducesDifferentOutput(int keySizeInBits)
//        {
//            string privateKeyXml, publicKeyXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateKeyXml, out publicKeyXml, keySizeInBits);
//            var encryptedAsBase64 = new HashSet<string>();
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                var inputBytes = GetRandomBytes(1, ((keySizeInBits - 384) / 8) + 7);
//                for (int i = 0; i < 5; ++i)
//                {
//                    encryptedAsBase64.Add(Convert.ToBase64String(algorithm.EncryptBytes(inputBytes, publicKeyXml)));
//                }
//            }
//            Assert.AreEqual(5, encryptedAsBase64.Count, "Should be 5 distinct values");
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        public void TestCreatePublicKeyFromPrivateKey(int keySizeInBits)
//        {
//            string privateKeyXml, publicKeyXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateKeyXml, out publicKeyXml, keySizeInBits);
//            string publicKeyXml2 = Asymmetric_RSA.GetPublicKeyFromPrivateKey(privateKeyXml);
//            Assert.AreEqual(publicKeyXml, publicKeyXml2);
//        }

//        [TestMethod]
//        [DataRow(384, null)]
//        [DataRow(1024, null)]
//        [DataRow(2048, null)]
//        [DataRow(4096, null)]
//        [DataRow(384, 0)]
//        [DataRow(1024, 0)]
//        [DataRow(2048, 0)]
//        [DataRow(4096, 0)]
//        [DataRow(384, 1)]
//        [DataRow(1024, 1)]
//        [DataRow(2048, 1)]
//        [DataRow(4096, 1)]
//        [DataRow(384, 6)]
//        [DataRow(1024, 86)]
//        [DataRow(2048, 214)]
//        [DataRow(4096, 470)]
//        public void TestEncryptBytes(int keySizeInBits, int? numBytes)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            byte[] input = null;
//            if (numBytes.HasValue)
//            {
//                input = GetRandomBytes(numBytes.Value, numBytes.Value);
//            }
//            byte[] encrypted, decrypted;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptBytes(input, publicXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                decrypted = algorithm.DecryptBytes(encrypted, privateXml);
//            }
//            if (input == null)
//            {
//                Assert.IsNull(encrypted, "encrypted");
//                Assert.IsNull(decrypted, "decrypted");
//            }
//            else
//            {
//                Assert.IsTrue(encrypted.Length >= numBytes, "encrypted.Length");
//                Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
//            }
//        }

//        [TestMethod]
//        [DataRow(384, null)]
//        [DataRow(1024, null)]
//        [DataRow(2048, null)]
//        [DataRow(4096, null)]
//        [DataRow(384, 0)]
//        [DataRow(1024, 0)]
//        [DataRow(2048, 0)]
//        [DataRow(4096, 0)]
//        [DataRow(384, 1)]
//        [DataRow(1024, 1)]
//        [DataRow(2048, 1)]
//        [DataRow(4096, 1)]
//        [DataRow(384, 6)]
//        [DataRow(1024, 86)]
//        [DataRow(2048, 214)]
//        [DataRow(4096, 470)]
//        public void TestEncryptString(int keySizeInBits, int? numChars)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            string input = null;
//            if (numChars.HasValue)
//            {
//                input = GetRandomString(numChars.Value, numChars.Value);
//            }

//            byte[] encrypted;
//            string decrypted;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptString(input, publicXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                decrypted = algorithm.DecryptBytes(encrypted, privateXml).AsString();
//            }
//            if (input == null)
//            {
//                Assert.IsNull(encrypted, "encrypted");
//                Assert.IsNull(decrypted, "decrypted");
//            }
//            else
//            {
//                Assert.IsTrue(encrypted.Length >= input.Length, "encrypted.Length");
//                Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
//            }
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        public void TestUnicodeString(int keySizeInBits)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            const string input = "\u01f0";

//            byte[] encrypted;
//            string decrypted;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptString(input, publicXml);
//            }
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                decrypted = algorithm.DecryptBytes(encrypted, privateXml).AsString();
//            }
//            Assert.IsTrue(encrypted.Length >= input.Length, "encrypted.Length");
//            Assert.IsTrue(decrypted.SequenceEqual(input), "Decrypted does not match original.");
//        }

//        [TestMethod]
//        [DataRow(384)]
//        [DataRow(1024)]
//        [DataRow(2048)]
//        [DataRow(4096)]
//        [ExpectedException(typeof(CryptographicException))]
//        public void TestIncorrectKeyFails(int keySizeInBits)
//        {
//            string privateXml, publicXml;
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            byte[] input = GetRandomBytes(6, 6);
//            byte[] encrypted;
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                encrypted = algorithm.EncryptBytes(input, publicXml);
//            }
//            Asymmetric_RSA.GenerateRandomPrivateKey(out privateXml, out publicXml, keySizeInBits);
//            using (var algorithm = new Asymmetric_RSA())
//            {
//                algorithm.DecryptBytes(encrypted, privateXml);
//            }
//        }
//    }
//}
