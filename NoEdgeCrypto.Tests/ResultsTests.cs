using System;
using System.Linq;
using System.Text;
using NoEdgeCrypto.Core.Converters;
using NoEdgeCrypto.Core.Results;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests
{
    [TestClass]
    public class ResultsTests
        : BaseTest
    {
        [TestMethod]
        public void TestAsBytes()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            byte[] after = res.AsBytes();
            Assert.IsTrue(before.SequenceEqual(after));
            
            res = new DecryptionResults(before);
            after = res.AsBytes();
            Assert.IsTrue(before.SequenceEqual(after));

            res = new HashResults(before);
            after = res.AsBytes();
            Assert.IsTrue(before.SequenceEqual(after));
        }

        [TestMethod]
        public void TestAsBase64()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsBase64();
            Assert.IsTrue(Convert.ToBase64String(before).SequenceEqual(after));
            
            res = new DecryptionResults(before);
            after = res.AsBase64();
            Assert.IsTrue(Convert.ToBase64String(before).SequenceEqual(after));

            res = new HashResults(before);
            after = res.AsBase64();
            Assert.IsTrue(Convert.ToBase64String(before).SequenceEqual(after));
        }


        [TestMethod]
        public void TestAsAscii85()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsAscii85();
            Assert.IsTrue(Ascii85Converter.BytesToAscii85(before).SequenceEqual(after));
            
            res = new DecryptionResults(before);
            after = res.AsAscii85();
            Assert.IsTrue(Ascii85Converter.BytesToAscii85(before).SequenceEqual(after));

            res = new HashResults(before);
            after = res.AsAscii85();
            Assert.IsTrue(Ascii85Converter.BytesToAscii85(before).SequenceEqual(after));
        }

        [TestMethod]
        public void TestAsHexNoDelimiterLower()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsHex(false, null);
            var expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);
            
            res = new DecryptionResults(before);
            after = res.AsHex(false, null);
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);

            res = new HashResults(before);
            after = res.AsHex(false, null);
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);
        }

        [TestMethod]
        public void TestAsHexNoDelimiterUpper()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsHex(true, null);
            var expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);
            
            res = new DecryptionResults(before);
            after = res.AsHex(true, null);
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);

            res = new HashResults(before);
            after = res.AsHex(true, null);
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);
        }

        [TestMethod]
        public void TestAsHexDelimiterLower()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsHex(false, '-');
            var expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("-");
                }
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);
            
            res = new DecryptionResults(before);
            after = res.AsHex(false, '-');
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("-");
                }
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);

            res = new HashResults(before);
            after = res.AsHex(false, '-');
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("-");
                }
                expected.Append(b.ToString("x2"));
            }
            Assert.AreEqual(expected.ToString(), after);
        }

        [TestMethod]
        public void TestAsHexDelimiterUpper()
        {
            byte[] before = GetRandomBytes(200, 300);
            BinaryResults res = new EncryptionResults(before);
            string after = res.AsHex(true, '+');
            var expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("+");
                }
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);
            
            res = new DecryptionResults(before);
            after = res.AsHex(true, '+');
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("+");
                }
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);

            res = new HashResults(before);
            after = res.AsHex(true, '+');
            expected = new StringBuilder();
            foreach (byte b in before)
            {
                if (expected.Length > 0)
                {
                    expected.Append("+");
                }
                expected.Append(b.ToString("X2"));
            }
            Assert.AreEqual(expected.ToString(), after);
        }

        [TestMethod]
        public void TestAsString()
        {
            string input = GetRandomString(200, 300);
            var before = Encoding.UTF8.GetBytes(input);
            var decryptionResults = new DecryptionResults(before);
            var after = decryptionResults.AsString(Encoding.UTF8);
            Assert.AreEqual(input, after);
        }
    }
}
