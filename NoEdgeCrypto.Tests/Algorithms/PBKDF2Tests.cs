using System;
using System.Collections.Generic;
using System.Linq;
using NoEdgeCrypto.Core.Algorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class PBKDF2Tests
        : BaseTest
    {
        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void TestEmptySalt()
        {
            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            PBKDF2.ComputeHash(password, out salt);
            PBKDF2.ComputeHash(password, new byte[0]);
        }

        [TestMethod]
        public void TestEmptyPassphrase()
        {
            string password = string.Empty;
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(password, salt);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestShortPassphrase()
        {
            const string PASSWORD = "abc";
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(PASSWORD, out salt);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(PASSWORD, salt);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestLongPassphrase()
        {
            const string PASSWORD = "asdhfjkzxcyvu8zopxhf DSJKFHSJLFHKJLSDFHKJXHCVJX*F(#$kdsfkjashdfkDKHL@#LJHDFJF";
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(PASSWORD, out salt);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(PASSWORD, salt);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestShortHash()
        {
            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt, 16384, 4);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(4, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(password, salt, 16384, 4);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestLongHash()
        {
            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt, 16384, 128);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(128, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(password, salt, 16384, 128);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestShortSalt()
        {
            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt, 16384, 32, 8);
            Assert.AreEqual(8, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(password, salt);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestLongSalt()
        {
            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt, 16384, 32, 128);
            Assert.AreEqual(128, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = PBKDF2.ComputeHash(password, salt);
            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");
        }

        [TestMethod]
        public void TestSamePassphraseGeneratesSameHash()
        {
            var hashes = new HashSet<string>();

            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            var hash2 = new byte[0];
            for (int i = 0; i < 20; ++i)
            {
                hash2 = PBKDF2.ComputeHash(password, salt);
                hashes.Add(Convert.ToBase64String(hash2));
            }

            Assert.IsTrue(hash1.SequenceEqual(hash2), "Hashes should be equal.");

            Assert.AreEqual(1, hashes.Count, "Number of unique hashes");
        }

        [TestMethod]
        public void TestDifferentIterationsProducesDifferentResults()
        {
            var hashes = new HashSet<string>();

            string password = Guid.NewGuid().ToString("N");
            byte[] salt;
            var hash1 = PBKDF2.ComputeHash(password, out salt);
            Assert.AreEqual(32, salt.Length, "Salt length");
            Assert.AreEqual(32, hash1.Length, "Hash1 length");
            for (int i = 0; i < 20; ++i)
            {
                byte[] hash2 = PBKDF2.ComputeHash(password, salt, 1000 + i);
                hashes.Add(Convert.ToBase64String(hash2));
            }

            Assert.AreEqual(20, hashes.Count, "Number of unique hashes");
        }
    }
}
