using System;
using NoEdgeCrypto.Core.Converters;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace NoEdgeSoftware.Cryptography.Tests
{
    [TestClass]
    public class Ascii85ConverterTests
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
        public void TestAscii85ToBytes(string input, string expectedAscii85)
        {
            if (input == null)
            {
                Assert.IsNull(Ascii85Converter.Ascii85ToBytes(input));
            }
            else
            {
                Assert.AreEqual(expectedAscii85, Convert.ToBase64String(Ascii85Converter.Ascii85ToBytes(Ascii85Converter.BytesToAscii85(HexConverter.HexToBytes(input)))));
            }
        }
    }
}
