using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NoEdgeCrypto.Core.Algorithms.HashAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Hash_SHA256Tests
        : BaseTest
    {
        private HashAlgorithmBase GetAlgo()
        {
            return new Hash_SHA256();
        }

        [TestMethod]
        public void TestBytesToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234"));
            AssertBytesEqual("6oJ44MYHcRyrh25FRn9cngUl0xYei798C2atOoCjkpM=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA256.Create())
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
            AssertBytesEqual("6oJ44MYHcRyrh25FRn9cngUl0xYei798C2atOoCjkpM=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                string s = GetRandomString(1, 1000);
                using (var algo = SHA256.Create())
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
            AssertBytesEqual("6oJ44MYHcRyrh25FRn9cngUl0xYei798C2atOoCjkpM=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] randomBytes = GetRandomBytes(1, 1000);
                byte[] hash;
                using (var algo = SHA256.Create())
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
            Assert.AreEqual("6oJ44MYHcRyrh25FRn9cngUl0xYei798C2atOoCjkpM=", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA256.Create())
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
            Assert.AreEqual("EA8278E0C607711CAB876E45467F5C9E0525D3161E8BBF7C0B66AD3A80A39293", result);
            result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex(true, '+');
            Assert.AreEqual("EA+82+78+E0+C6+07+71+1C+AB+87+6E+45+46+7F+5C+9E+05+25+D3+16+1E+8B+BF+7C+0B+66+AD+3A+80+A3+92+93", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA256.Create())
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
