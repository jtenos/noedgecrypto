using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using NoEdgeCrypto.Core;
using NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using NoEdgeCrypto.Tests;
using NoEdgeCrypto.Core.Algorithms.SymmetricAlgorithms.Passphrase;

namespace NoEdgeSoftware.Cryptography.Tests.Algorithms
{
    [TestClass]
    public class AESCBCTestsPassphrase
        : BaseTest
    {
        private SymmetricAlgorithmBase_Passphrase _symmetric;
        private string _passphrase;

        [TestInitialize]
        public void SetUp()
        {
            _symmetric = new Symmetric_AES_CBC_Passphrase();
            _passphrase = Guid.NewGuid().ToString();
        }

        [TestCleanup]
        public void TearDown()
        {
            ((IDisposable)_symmetric).Dispose();
        }

        [TestMethod]
        public void TestZeroBytes()
        {
            var input = new byte[0];
            byte[] encrypted = _symmetric.EncryptBytes(input, _passphrase);
            Assert.IsTrue(encrypted.Length > 64, "encrypted.Length");

            byte[] decrypted = _symmetric.DecryptBytes(encrypted, _passphrase);
            Assert.AreEqual(0, decrypted.Length, "decrypted.Length");
        }

        [TestMethod]
        public void TestOneByte()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(1);
            byte[] encrypted = _symmetric.EncryptBytes(input, _passphrase);
            Assert.IsTrue(encrypted.Length > 48, "encrypted.Length");

            byte[] decrypted = _symmetric.DecryptBytes(encrypted, _passphrase);
            Assert.IsTrue(input.SequenceEqual(decrypted), string.Format("{0} | {1}",
                Convert.ToBase64String(input), Convert.ToBase64String(decrypted)));
        }

        [TestMethod]
        public void TestBytesSmall()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(100);
            byte[] encrypted = _symmetric.EncryptBytes(input, _passphrase);
            Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");

            byte[] decrypted = _symmetric.DecryptBytes(encrypted, _passphrase);
            Assert.IsTrue(input.SequenceEqual(decrypted), string.Format("{0} | {1}",
                Convert.ToBase64String(input), Convert.ToBase64String(decrypted)));
        }

        [TestMethod]
        public void TestBytesMedium()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(3200);
            byte[] encrypted = _symmetric.EncryptBytes(input, _passphrase);
            Assert.IsTrue(encrypted.Length > 3200, "encrypted.Length");

            byte[] decrypted = _symmetric.DecryptBytes(encrypted, _passphrase);
            Assert.IsTrue(input.SequenceEqual(decrypted), "input does not match decrypted");
        }

        [TestMethod]
        public void TestBytesLarge()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(250000);
            byte[] encrypted = _symmetric.EncryptBytes(input, _passphrase);
            Assert.IsTrue(encrypted.Length > 250000, "encrypted.Length");

            byte[] decrypted = _symmetric.DecryptBytes(encrypted, _passphrase);
            Assert.IsTrue(input.SequenceEqual(decrypted), "input does not match decrypted");
        }

        [TestMethod]
        public void TestMemoryStream()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(15000);
            byte[] encrypted;
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    _symmetric.EncryptStream(inputStream, outputStream, _passphrase);
                    encrypted = outputStream.ToArray();
                }
            }

            Assert.IsTrue(encrypted.Length > 15000, "encrypted.Length");

            byte[] decrypted;
            using (var inputStream = new MemoryStream(encrypted))
            {
                using (var outputStream = new MemoryStream())
                {
                    _symmetric.DecryptStream(inputStream, outputStream, _passphrase);
                    decrypted = outputStream.ToArray();
                }
            }
            Assert.IsTrue(input.SequenceEqual(decrypted), "input does not match decrypted");
        }

        [TestMethod]
        public void TestFileStream()
        {
            string originalFileName = GetTempFileName();
            using (var tempFileStream = File.Create(originalFileName))
            {
                for (int i = 0; i < 100; ++i)
                {
                    tempFileStream.Write(SecureRandomizer.GetRandomBytes(1024), 0, 1024);
                }
            }

            string encryptedFileName = GetTempFileName();
            using (var inputStream = File.Open(originalFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var outputStream = File.Create(encryptedFileName))
                {
                    _symmetric.EncryptStream(inputStream, outputStream, _passphrase);
                }
            }

            string decryptedFileName = GetTempFileName();
            using (var inputStream = File.Open(encryptedFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var outputStream = File.Create(decryptedFileName))
                {
                    _symmetric.DecryptStream(inputStream, outputStream, _passphrase);
                }
            }

            var originalFile = new FileInfo(originalFileName);
            var encryptedFile = new FileInfo(encryptedFileName);
            var decryptedFile = new FileInfo(decryptedFileName);

            Assert.IsTrue(encryptedFile.Length > originalFile.Length, "Encrypted file should be larger than original.");
            Assert.AreEqual(originalFile.Length, decryptedFile.Length, "Original file should be the same size as original.");

            var buffer1 = new byte[8096];
            var buffer2 = new byte[8096];
            using (var originalStream = File.Open(originalFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var decryptedStream = File.Open(decryptedFileName, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    while ((originalStream.Read(buffer1, 0, buffer1.Length) > 0))
                    {
                        decryptedStream.Read(buffer2, 0, buffer2.Length);
                        Assert.IsTrue(buffer1.SequenceEqual(buffer2), "Files do not match.");
                    }
                }
            }
        }

        [TestMethod]
        public void TestEmptyMemoryStream()
        {
            byte[] input = SecureRandomizer.GetRandomBytes(0);
            byte[] encrypted;
            using (var inputStream = new MemoryStream(input))
            {
                using (var outputStream = new MemoryStream())
                {
                    _symmetric.EncryptStream(inputStream, outputStream, _passphrase);
                    encrypted = outputStream.ToArray();
                }
            }

            Assert.IsTrue(encrypted.Length > 64, "encrypted.Length");

            byte[] decrypted;
            using (var inputStream = new MemoryStream(encrypted))
            {
                using (var outputStream = new MemoryStream())
                {
                    _symmetric.DecryptStream(inputStream, outputStream, _passphrase);
                    decrypted = outputStream.ToArray();
                }
            }
            Assert.AreEqual(0, decrypted.Length, "decrypted.Length");
        }

        [TestMethod]
        public void TestEmptyFileStream()
        {
            string originalFileName = GetTempFileName();
            using (File.Create(originalFileName))
            {
            }

            string encryptedFileName = GetTempFileName();
            using (var inputStream = File.Open(originalFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var outputStream = File.Create(encryptedFileName))
                {
                    _symmetric.EncryptStream(inputStream, outputStream, _passphrase);
                }
            }

            string decryptedFileName = GetTempFileName();
            using (var inputStream = File.Open(encryptedFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var outputStream = File.Create(decryptedFileName))
                {
                    _symmetric.DecryptStream(inputStream, outputStream, _passphrase);
                }
            }

            var encryptedFile = new FileInfo(encryptedFileName);
            var decryptedFile = new FileInfo(decryptedFileName);

            Assert.IsTrue(encryptedFile.Length > 64, "encryptedFile.Length");
            Assert.AreEqual(0, decryptedFile.Length, "encryptedFile.Length");
        }

        [TestMethod]
        public void TestFile()
        {
            string originalFileName = GetTempFileName();
            using (var tempFileStream = File.Create(originalFileName))
            {
                for (int i = 0; i < 100; ++i)
                {
                    tempFileStream.Write(SecureRandomizer.GetRandomBytes(1024), 0, 1024);
                }
            }

            string encryptedFileName = GetTempFileName();
            _symmetric.EncryptFileToFile(originalFileName, encryptedFileName, _passphrase);

            string decryptedFileName = GetTempFileName();
            _symmetric.DecryptFileToFile(encryptedFileName, decryptedFileName, _passphrase);

            var originalFile = new FileInfo(originalFileName);
            var encryptedFile = new FileInfo(encryptedFileName);
            var decryptedFile = new FileInfo(decryptedFileName);

            Assert.IsTrue(encryptedFile.Length > originalFile.Length, "Encrypted file should be larger than original.");
            Assert.AreEqual(originalFile.Length, decryptedFile.Length, "Original file should be the same size as original.");

            var buffer1 = new byte[8096];
            var buffer2 = new byte[8096];
            using (var originalStream = File.Open(originalFileName, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                using (var decryptedStream = File.Open(decryptedFileName, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    while ((originalStream.Read(buffer1, 0, buffer1.Length) > 0))
                    {
                        decryptedStream.Read(buffer2, 0, buffer2.Length);
                        Assert.IsTrue(buffer1.SequenceEqual(buffer2), "Files do not match.");
                    }
                }
            }
        }

        [TestMethod]
        public void TestEmptyFile()
        {
            string originalFileName = GetTempFileName();
            using (File.Create(originalFileName))
            {
            }

            string encryptedFileName = GetTempFileName();
            _symmetric.EncryptFileToFile(originalFileName, encryptedFileName, _passphrase);

            string decryptedFileName = GetTempFileName();
            _symmetric.DecryptFileToFile(encryptedFileName, decryptedFileName, _passphrase);

            var encryptedFile = new FileInfo(encryptedFileName);
            var decryptedFile = new FileInfo(decryptedFileName);

            Assert.IsTrue(encryptedFile.Length > 32, "encryptedFile.Length");
            Assert.AreEqual(0, decryptedFile.Length, "encryptedFile.Length");
        }

        [TestMethod]
        public void TestString()
        {
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100));
            string encrypted = _symmetric.EncryptString(input, _passphrase).AsBase64();
            Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");

            string decrypted = _symmetric.DecryptString(encrypted, _passphrase).AsString();
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        public void TestUnicodeString()
        {
            string input = Convert.ToBase64String(SecureRandomizer.GetRandomBytes(100)) + "\u01e2\u01f0\u020e\u0229";
            string encrypted = _symmetric.EncryptString(input, _passphrase).AsBase64();
            Assert.IsTrue(encrypted.Length > 100, "encrypted.Length");

            string decrypted = _symmetric.DecryptString(encrypted, _passphrase).AsString();
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        public void TestEmptyString()
        {
            string input = string.Empty;
            string encrypted = _symmetric.EncryptString(input, _passphrase).AsBase64();
            Assert.IsTrue(encrypted.Length > 64, "encrypted.Length");
            string decrypted = _symmetric.DecryptString(encrypted, _passphrase).AsString();
            Assert.AreEqual(input, decrypted, string.Format("{0} | {1}", input, decrypted));
        }

        [TestMethod]
        public void TestNullBytes()
        {
            byte[] encrypted = _symmetric.EncryptBytes(null, _passphrase);
            Assert.IsNull(encrypted, "encrypted");

            byte[] decrypted = _symmetric.DecryptBytes(null, _passphrase);
            Assert.IsNull(decrypted, "decrypted");
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestNullInputStream()
        {
            using (var outputStream = new MemoryStream())
            {
                _symmetric.EncryptStream(null, outputStream, _passphrase);
            }
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void TestNullOutputStream()
        {
            using (var inputStream = new MemoryStream())
            {
                _symmetric.EncryptStream(inputStream, null, _passphrase);
            }
        }

        [TestMethod]
        public void TestNullString()
        {
            string encrypted = _symmetric.EncryptString(null, _passphrase).AsBase64();
            Assert.IsNull(encrypted, "encrypted");

            string decrypted = _symmetric.DecryptString(null, _passphrase).AsString();
            Assert.IsNull(decrypted, "decrypted");
        }

        [TestMethod]
        [ExpectedException(typeof(FileNotFoundException))]
        public void TestInputFileNotExists()
        {
            string encryptedFileName = GetTempFileName();
            _symmetric.EncryptFileToFile(GetTempFileName(), encryptedFileName, _passphrase);
        }

        [TestMethod]
        [ExpectedException(typeof(IOException))]
        public void TestOutputFileAlreadyExists()
        {
            string originalFileName = GetTempFileName();
            File.WriteAllBytes(originalFileName, new byte[] { 1, 2, 3, 4 });
            string encryptedFileName = GetTempFileName();
            File.WriteAllBytes(encryptedFileName, new byte[] { 1, 2, 3, 4 });
            _symmetric.EncryptFileToFile(originalFileName, encryptedFileName, _passphrase);
        }

        [TestMethod]
        public void TestSameInputProducesDifferentOutput()
        {
            var inputBytes = SecureRandomizer.GetRandomBytes(1024);
            var encryptedAsBase64 = new HashSet<string>();
            for (int i = 0; i < 20; ++i)
            {
                encryptedAsBase64.Add(Convert.ToBase64String(_symmetric.EncryptBytes(inputBytes, _passphrase)));
            }
            Assert.AreEqual(20, encryptedAsBase64.Count, "Should be 20 distinct values");
        }

        [TestMethod]
        public void TestSerializableObject()
        {
            var rand = new Random();
            for (int i = 0; i < 20; ++i)
            {
                var foo = new Foo
                {
                    Id = rand.Next(),
                    Name = Guid.NewGuid().ToString(),
                    Misc = new[] { Guid.NewGuid().ToString(), Guid.NewGuid().ToString() }
                };
                byte[] enc = _symmetric.EncryptSerializableObject(foo, _passphrase);

                var decrypted = _symmetric.DecryptSerializableObject<Foo>(enc, _passphrase);
                Assert.AreEqual(foo, decrypted);
            }
        }
    }
}
