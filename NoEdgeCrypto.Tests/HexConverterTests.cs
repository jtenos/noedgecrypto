using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Core.Converters;

namespace NoEdgeSoftware.Cryptography.Tests
{
    [TestClass]
    public class HexConverterTests
        : BaseTest
    {
        [TestMethod]
        [DataRow(null, null)]
        [DataRow("", "")]
        [DataRow("ab", "qw==")]
        [DataRow("1234567890abcdef", "EjRWeJCrze8=")]
        [DataRow("1234567890ABCDEF", "EjRWeJCrze8=")]
        [DataRow("ABCDEF1234567890", "q83vEjRWeJA=")]
        [DataRow("AB-CD-EF-12-34-56-78-90", "q83vEjRWeJA=")]
        public void TestHexToBytes(string input, string expectedBase64)
        {
            if (input == null)
            {
                Assert.IsNull(HexConverter.HexToBytes(input));
            }
            else
            {
                Assert.AreEqual(expectedBase64, Convert.ToBase64String(HexConverter.HexToBytes(input)));
            }
        }

        [TestMethod]
        [DataRow(null, null, true, null)]
        [DataRow(null, null, false, null)]
        [DataRow("qw==", null, true, "AB")]
        [DataRow("qw==", null, false, "ab")]
        [DataRow("EjRWeJCrze8=", null, true, "1234567890ABCDEF")]
        [DataRow("EjRWeJCrze8=", null, false, "1234567890abcdef")]
        [DataRow("q83vEjRWeJA=", null, true, "ABCDEF1234567890")]
        [DataRow("q83vEjRWeJA=", null, false, "abcdef1234567890")]
        [DataRow("qw==", '-', true, "AB")]
        [DataRow("qw==", '-', false, "ab")]
        [DataRow("EjRWeJCrze8=", '-', true, "12-34-56-78-90-AB-CD-EF")]
        [DataRow("EjRWeJCrze8=", '-', false, "12-34-56-78-90-ab-cd-ef")]
        [DataRow("q83vEjRWeJA=", '-', true, "AB-CD-EF-12-34-56-78-90")]
        [DataRow("q83vEjRWeJA=", '-', false, "ab-cd-ef-12-34-56-78-90")]

        public void TestBytesToHex(string inputBase64, char? delimiter, bool upperCase, string expected)
        {
            if (inputBase64 == null)
            {
                Assert.IsNull(HexConverter.BytesToHex(null));
            }
            else
            {
                Assert.AreEqual(expected, HexConverter.BytesToHex(Convert.FromBase64String(inputBase64), delimiter, upperCase));
            }
        }
    }
}
