using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NoEdgeCrypto.Core.Algorithms.HashAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Hash_SHA384_Tests
        : BaseTest
    {
        private HashAlgorithmBase GetAlgo()
        {
            return new Hash_SHA384();
        }

        [TestMethod]
        public void TestBytesToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234"));
            AssertBytesEqual("uxTDx5QPbb0pQrt3XPaWIZqQgs5xyJupSlYfyDpjzEz161C38u7J7bjqwDNp5q7A", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA384.Create())
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
            AssertBytesEqual("uxTDx5QPbb0pQrt3XPaWIZqQgs5xyJupSlYfyDpjzEz161C38u7J7bjqwDNp5q7A", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                string s = GetRandomString(1, 1000);
                using (var algo = SHA384.Create())
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
            AssertBytesEqual("uxTDx5QPbb0pQrt3XPaWIZqQgs5xyJupSlYfyDpjzEz161C38u7J7bjqwDNp5q7A", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] randomBytes = GetRandomBytes(1, 1000);
                byte[] hash;
                using (var algo = SHA384.Create())
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
            Assert.AreEqual("uxTDx5QPbb0pQrt3XPaWIZqQgs5xyJupSlYfyDpjzEz161C38u7J7bjqwDNp5q7A", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA384.Create())
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
            Assert.AreEqual("BB14C3C7940F6DBD2942BB775CF696219A9082CE71C89BA94A561FC83A63CC4CF5EB50B7F2EEC9EDB8EAC03369E6AEC0", result);
            result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex(true, '+');
            Assert.AreEqual("BB+14+C3+C7+94+0F+6D+BD+29+42+BB+77+5C+F6+96+21+9A+90+82+CE+71+C8+9B+A9+4A+56+1F+C8+3A+63+CC+4C+F5+EB+50+B7+F2+EE+C9+ED+B8+EA+C0+33+69+E6+AE+C0", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA384.Create())
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
