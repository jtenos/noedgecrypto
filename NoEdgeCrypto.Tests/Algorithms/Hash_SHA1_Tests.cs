using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NoEdgeCrypto.Core.Algorithms.HashAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Hash_SHA1Tests
        : BaseTest
    {
        private HashAlgorithmBase GetAlgo()
        {
            return new Hash_SHA1();
        }

        [TestMethod]
        public void TestBytesToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234"));
            AssertBytesEqual("4OT5DLZENjBeEJ/5o2uwQhfOXY4=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA1.Create())
                {
                    byte[] hash = algo.ComputeHash(bytes);
                    AssertBytesEqual(hash, GetAlgo().HashBytes(bytes));
                }
            }
        }

        [TestMethod]
        public void TestStringToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashString("Test 1234");
            AssertBytesEqual("4OT5DLZENjBeEJ/5o2uwQhfOXY4=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                string s = GetRandomString(1, 1000);
                using (var algo = SHA1.Create())
                {
                    byte[] hash = algo.ComputeHash(Encoding.UTF8.GetBytes(s));
                    AssertBytesEqual(hash, GetAlgo().HashString(s));
                }
            }
        }

        [TestMethod]
        public void TestStreamToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashStream(new MemoryStream(Encoding.UTF8.GetBytes("Test 1234")));
            AssertBytesEqual("4OT5DLZENjBeEJ/5o2uwQhfOXY4=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] randomBytes = GetRandomBytes(1, 1000);
                byte[] hash;
                using (var algo = SHA1.Create())
                {
                    hash = algo.ComputeHash(randomBytes);
                }
                AssertBytesEqual(hash, GetAlgo().HashStream(new MemoryStream(randomBytes)));
            }
        }

        [TestMethod]
        public void TestBytesToBase64()
        {
            // Known value
            string result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsBase64();
            Assert.AreEqual("4OT5DLZENjBeEJ/5o2uwQhfOXY4=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA1.Create())
                {
                    byte[] hash = algo.ComputeHash(bytes);
                    Assert.AreEqual(Convert.ToBase64String(hash), GetAlgo().HashBytes(bytes).AsBase64());
                }
            }
        }

        [TestMethod]
        public void TestBytesToHex()
        {
            // Known value
            string result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex();
            Assert.AreEqual("E0E4F90CB64436305E109FF9A36BB04217CE5D8E", result);
            result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex(true, '+');
            Assert.AreEqual("E0+E4+F9+0C+B6+44+36+30+5E+10+9F+F9+A3+6B+B0+42+17+CE+5D+8E", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA1.Create())
                {
                    byte[] hash = algo.ComputeHash(bytes);
                    var sb = new StringBuilder();
                    foreach (byte b in hash)
                    {
                        sb.AppendFormat("{0:X2}", b);
                    }
                    Assert.AreEqual(sb.ToString(), GetAlgo().HashBytes(bytes).AsHex());
                }
            }
        }

        private void AssertBytesEqual(string expectedBase64, byte[] actual)
        {
            Assert.AreEqual(expectedBase64, Convert.ToBase64String(actual), "Bytes do not match");
        }

        private void AssertBytesEqual(byte[] expectedBytes, byte[] actual)
        {
            AssertBytesEqual(Convert.ToBase64String(expectedBytes), actual);
        }
    }
}
