using System;
using System.IO;
using System.Text;

namespace NoEdgeSoftware.Cryptography.Tests
{
    public class BaseTest
    {
        private static readonly Random _rand = new Random();
        protected string GetTempFileName()
        {
            return Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        }

        protected string GetRandomString(int minLength, int maxLength)
        {
            const string VALID_CHARS = "abcdefghijklmopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()[]\\{}|;':\",./<>?`~";
            var sb = new StringBuilder();
            int numLetters = _rand.Next(minLength, maxLength);
            for (int i = 0; i < numLetters; ++i)
            {
                sb.Append(VALID_CHARS[_rand.Next(0, VALID_CHARS.Length)]);
            }
            return sb.ToString();
        }

        protected byte[] GetRandomBytes(int minLength, int maxLength)
        {
            var bytes = new byte[_rand.Next(minLength, maxLength)];
            _rand.NextBytes(bytes);
            return bytes;
        }
    }
}
