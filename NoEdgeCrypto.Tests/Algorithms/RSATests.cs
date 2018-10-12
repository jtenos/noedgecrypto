using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NoEdgeCrypto.Core;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Core.Algorithms.AsymmetricAlgorithms;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class RSATests
        : BaseTest
    {
        private AsymmetricAlgorithmBase _asymmetric;
        private string _privateKey;
        private string _publicKey;

        [TestInitialize]
        public void SetUp()
        {
        }

        [TestCleanup]
        public void TearDown()
        {
            if (_asymmetric != null)
            {
                ((IDisposable)_asymmetric).Dispose();
            }
            _asymmetric = null;
        }

        private void Reset(int keySize = 1024)
        {
            _asymmetric = new Asymmetric_RSA();
            Asymmetric_RSA.GenerateRandomPrivateKey(out _privateKey, out _publicKey);
        }

        [TestMethod]
        public void TestZeroBytes()
        {
            Reset();
            var input = new Byte[0];
            byte[] encrypted = _asymmetric.EncryptBytes(input, _publicKey);
            Assert.AreEqual(128, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.AreEqual(0, decrypted.Length, "decrypted.Length");
        }

        [TestMethod]
        public void TestOneByte()
        {
            Reset();
            byte[] input = SecureRandomizer.GetRandomBytes(1);
            byte[] encrypted = _asymmetric.EncryptBytes(input, _publicKey);
            Assert.AreEqual(128, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.IsTrue(input.SequenceEqual(decrypted), string.Format("{0} | {1}",
                Convert.ToBase64String(input), Convert.ToBase64String(decrypted)));
        }

        [TestMethod]
        public void TestBytes()
        {
            Reset();
            byte[] input = SecureRandomizer.GetRandomBytes(80);
            byte[] encrypted = _asymmetric.EncryptBytes(input, _publicKey);
            Assert.AreEqual(128, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.IsTrue(input.SequenceEqual(decrypted), string.Format("{0} | {1}",
                Convert.ToBase64String(input), Convert.ToBase64String(decrypted)));
        }

        [TestMethod]
        public void TestBytesMedium()
        {
            Reset(2048);
            byte[] input = SecureRandomizer.GetRandomBytes(120);
            byte[] encrypted = _asymmetric.EncryptBytes(input, _publicKey);
            Assert.AreEqual(256, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.IsTrue(input.SequenceEqual(decrypted), "input does not match decrypted");
        }

        [TestMethod]
        public void TestBytesLarge()
        {
            Reset(4096);
            byte[] input = SecureRandomizer.GetRandomBytes(240);
            byte[] encrypted = _asymmetric.EncryptBytes(input, _publicKey);
            Assert.AreEqual(512, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.IsTrue(input.SequenceEqual(decrypted), "input does not match decrypted");
        }

        [TestMethod]
        public void TestStringToBytes()
        {
            Reset();
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(50));
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] encrypted = _asymmetric.EncryptString(input, _publicKey);
            Assert.AreEqual(128, encrypted.Length, "encrypted.Length");
            byte[] decrypted = _asymmetric.DecryptBytes(encrypted, _privateKey);
            Assert.IsTrue(inputBytes.SequenceEqual(decrypted), string.Format("{0} | {1}",
                Convert.ToBase64String(inputBytes), Convert.ToBase64String(decrypted)));
        }

        [TestMethod]
        public void TestNullBytes()
        {
            Reset();
            byte[] encrypted = _asymmetric.EncryptBytes((byte[])null, _publicKey);
            Assert.IsNull(encrypted, "encrypted");
            byte[] decrypted = _asymmetric.DecryptBytes((byte[])null, _privateKey);
            Assert.IsNull(decrypted, "decrypted");
        }

        [TestMethod]
        public void TestNullString()
        {
            Reset();
            byte[] encrypted = _asymmetric.EncryptString((string)null, _publicKey);
            Assert.IsNull(encrypted, "encrypted");
            byte[] decrypted = _asymmetric.DecryptBytes((byte[])null, _privateKey);
            Assert.IsNull(decrypted, "decrypted");
        }

        [TestMethod]
        public void TestSameInputProducesDifferentOutput()
        {
            Reset();
            var inputBytes = SecureRandomizer.GetRandomBytes(80);
            var encryptedAsBase64 = new HashSet<string>();
            for (int i = 0; i < 20; ++i)
            {
                encryptedAsBase64.Add(Convert.ToBase64String(_asymmetric.EncryptBytes(inputBytes, _publicKey)));
            }
            Assert.AreEqual(20, encryptedAsBase64.Count, "Should be 100 distinct values");
        }

        [TestMethod]
        public void TestEncryptBytesToBase64()
        {
            Reset();
            var input = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            var base64Encrypted = _asymmetric.EncryptBytes(input, _publicKey).AsBase64();
            Convert.FromBase64String(base64Encrypted); // Just to ensure it's a valid base-64 string

            var decryptedBytes = _asymmetric.DecryptBase64(base64Encrypted, _privateKey);
            Assert.IsTrue(decryptedBytes.AsBytes().SequenceEqual(input), "{0} | {1}", Convert.ToBase64String(input),
                Convert.ToBase64String(decryptedBytes));

            var decryptedBase64 = _asymmetric.DecryptBase64(base64Encrypted, _privateKey).AsBase64();
            Assert.IsTrue(Convert.FromBase64String(decryptedBase64).SequenceEqual(input), "{0} | {1}", Convert.ToBase64String(input),
                decryptedBase64);
        }

        [TestMethod]
        public void TestEncryptStringToBase64()
        {
            Reset();
            const string INPUT = "hello world!";
            var base64Encrypted = _asymmetric.EncryptString(INPUT, _publicKey).AsBase64();
            Convert.FromBase64String(base64Encrypted); // Just to ensure it's a valid base-64 string

            var decryptedBytes = _asymmetric.DecryptBase64(base64Encrypted, _privateKey).AsBytes();
            Assert.IsTrue(decryptedBytes.SequenceEqual(Encoding.UTF8.GetBytes(INPUT)), "{0} | {1}",
                Convert.ToBase64String(Encoding.UTF8.GetBytes(INPUT)), Convert.ToBase64String(decryptedBytes));

            var decryptedBase64 = _asymmetric.DecryptBase64(base64Encrypted, _privateKey).AsBase64();
            Assert.IsTrue(Convert.FromBase64String(decryptedBase64).SequenceEqual(Encoding.UTF8.GetBytes(INPUT)),
                "{0} | {1}", Convert.ToBase64String(Encoding.UTF8.GetBytes(INPUT)), decryptedBase64);

            var decryptedString = _asymmetric.DecryptBase64(base64Encrypted, _privateKey).AsString();
            Assert.AreEqual(INPUT, decryptedString);
        }
    }
}
