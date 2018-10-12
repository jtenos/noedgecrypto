using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using NoEdgeCrypto.Core.Algorithms.HashAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class Hash_SHA512_Tests
        : BaseTest
    {
        private HashAlgorithmBase GetAlgo()
        {
            return new Hash_SHA512();
        }

        [TestMethod]
        public void TestBytesToBytes()
        {
            // Known value
            byte[] result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234"));
            AssertBytesEqual("iiQvp5s8N3Pusk1awQot1oJIpmG9her0G4nq0AAMf5csAzy+swUf+pJSTQW9bsLjlIh66hlG+ufpwnvjO640IA==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA512.Create())
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
            AssertBytesEqual("iiQvp5s8N3Pusk1awQot1oJIpmG9her0G4nq0AAMf5csAzy+swUf+pJSTQW9bsLjlIh66hlG+ufpwnvjO640IA==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                string s = GetRandomString(1, 1000);
                using (var algo = SHA512.Create())
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
            AssertBytesEqual("iiQvp5s8N3Pusk1awQot1oJIpmG9her0G4nq0AAMf5csAzy+swUf+pJSTQW9bsLjlIh66hlG+ufpwnvjO640IA==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] randomBytes = GetRandomBytes(1, 1000);
                byte[] hash;
                using (var algo = SHA512.Create())
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
            Assert.AreEqual("iiQvp5s8N3Pusk1awQot1oJIpmG9her0G4nq0AAMf5csAzy+swUf+pJSTQW9bsLjlIh66hlG+ufpwnvjO640IA==", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA512.Create())
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
            Assert.AreEqual("8A242FA79B3C3773EEB24D5AC10A2DD68248A661BD85EAF41B89EAD0000C7F972C033CBEB3051FFA92524D05BD6EC2E394887AEA1946FAE7E9C27BE33BAE3420", result);
            result = GetAlgo().HashBytes(Encoding.UTF8.GetBytes("Test 1234")).AsHex(true, '+');
            Assert.AreEqual("8A+24+2F+A7+9B+3C+37+73+EE+B2+4D+5A+C1+0A+2D+D6+82+48+A6+61+BD+85+EA+F4+1B+89+EA+D0+00+0C+7F+97+2C+03+3C+BE+B3+05+1F+FA+92+52+4D+05+BD+6E+C2+E3+94+88+7A+EA+19+46+FA+E7+E9+C2+7B+E3+3B+AE+34+20", result);

            // Random values
            for (int i = 0; i < 50; ++i)
            {
                byte[] bytes = GetRandomBytes(1, 1000);
                using (var algo = SHA512.Create())
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
