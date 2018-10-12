using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NoEdgeCrypto.Core.Algorithms.HashAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Hash_MD5Tests
        : BaseTest
    {
        private HashAlgorithmBase GetAlgo()
        {
            return new Hash_MD5();
        }

        [TestMethod]
        public void TestBytesToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234"));
            AssertBytesEqual("NVsXme9oaXUyWDLR+1gWVw==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = MD5.Create())
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
            AssertBytesEqual("NVsXme9oaXUyWDLR+1gWVw==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                string s = GetRandomString(1, 1000);
                using (var algo = MD5.Create())
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
            AssertBytesEqual("NVsXme9oaXUyWDLR+1gWVw==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] randomBytes = GetRandomBytes(1, 1000);
                byte[] hash;
                using (var algo = MD5.Create())
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
            Assert.AreEqual("NVsXme9oaXUyWDLR+1gWVw==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = MD5.Create())
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
            Assert.AreEqual("355B1799EF686975325832D1FB581657", result);
            result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex(true, '+');
            Assert.AreEqual("35+5B+17+99+EF+68+69+75+32+58+32+D1+FB+58+16+57", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = MD5.Create())
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
